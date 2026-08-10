package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testInstallationID = "0197f2c1-7b2a-7abc-8def-0123456789ab"

var testNow = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

func TestGenerateIdentityCreatesRequestNeutralP256CSR(t *testing.T) {
	material, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	if material.PrivateKey.Curve != elliptic.P256() {
		t.Fatal("expected P-256 private key")
	}
	request, err := ParseAndValidateCSR(material.CSRPEM)
	if err != nil {
		t.Fatalf("validate generated CSR: %v", err)
	}
	if request.Subject.String() != "" || len(request.DNSNames) != 0 ||
		len(request.EmailAddresses) != 0 || len(request.IPAddresses) != 0 ||
		len(request.URIs) != 0 || len(request.Extensions) != 0 {
		t.Fatal("generated CSR requested identity-bearing fields")
	}
	for _, output := range []string{material.String(), fmt.Sprintf("%#v", material)} {
		if strings.Contains(output, "PRIVATE KEY") || strings.Contains(output, "D:") {
			t.Fatal("formatted identity disclosed private key material")
		}
	}
}

func TestParseAndValidateCSRRejectsWrongAlgorithm(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, privateKey)
	if err != nil {
		t.Fatalf("create RSA CSR: %v", err)
	}
	requestPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER})
	if _, err := ParseAndValidateCSR(requestPEM); err == nil || !strings.Contains(err.Error(), "P-256") {
		t.Fatalf("expected P-256 rejection, got %v", err)
	}
}

func TestVerifyProfileAcceptsExactNodeCertificate(t *testing.T) {
	leaf, _ := issueNodeCertificate(t, nil, nil)
	if err := VerifyProfile(leaf, testInstallationID, testNow); err != nil {
		t.Fatalf("verify exact profile: %v", err)
	}
	fingerprint := DERFingerprint(leaf.Raw)
	if len(FingerprintHex(fingerprint)) != 64 {
		t.Fatal("expected lowercase SHA-256 fingerprint")
	}
}

func TestVerifyProfileRejectsWrongSAN(t *testing.T) {
	leaf, _ := issueNodeCertificate(t, func(template *x509.Certificate) {
		template.URIs = []*url.URL{{Scheme: "spiffe", Host: "scalevault", Path: "/installation/0197f2c1-7b2a-7abc-8def-0123456789ac"}}
	}, nil)
	if err := VerifyProfile(leaf, testInstallationID, testNow); err == nil || !strings.Contains(err.Error(), "URI SAN") {
		t.Fatalf("expected URI SAN rejection, got %v", err)
	}

	leaf, _ = issueNodeCertificate(t, func(template *x509.Certificate) {
		template.DNSNames = []string{"node.example"}
		template.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")}
	}, nil)
	if err := VerifyProfile(leaf, testInstallationID, testNow); err == nil || !strings.Contains(err.Error(), "DNS") {
		t.Fatalf("expected alternate SAN rejection, got %v", err)
	}
}

func TestVerifyProfileRejectsWrongAlgorithm(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	leaf, _ := issueNodeCertificate(t, nil, rsaKey)
	if err := VerifyProfile(leaf, testInstallationID, testNow); err == nil || !strings.Contains(err.Error(), "P-256") {
		t.Fatalf("expected algorithm rejection, got %v", err)
	}
}

func TestVerifyProfileRejectsWrongEKU(t *testing.T) {
	leaf, _ := issueNodeCertificate(t, func(template *x509.Certificate) {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}, nil)
	if err := VerifyProfile(leaf, testInstallationID, testNow); err == nil || !strings.Contains(err.Error(), "clientAuth") {
		t.Fatalf("expected EKU rejection, got %v", err)
	}
}

func TestVerifyProfileRejectsExpiredAndExcessiveValidity(t *testing.T) {
	expired, _ := issueNodeCertificate(t, func(template *x509.Certificate) {
		template.NotBefore = testNow.Add(-48 * time.Hour)
		template.NotAfter = testNow.Add(-24 * time.Hour)
	}, nil)
	if err := VerifyProfile(expired, testInstallationID, testNow); err == nil || !strings.Contains(err.Error(), "currently valid") {
		t.Fatalf("expected expiry rejection, got %v", err)
	}

	tooLong, _ := issueNodeCertificate(t, func(template *x509.Certificate) {
		template.NotBefore = testNow.Add(-time.Hour)
		template.NotAfter = template.NotBefore.Add(30*24*time.Hour + time.Second)
	}, nil)
	if err := VerifyProfile(tooLong, testInstallationID, testNow); err == nil || !strings.Contains(err.Error(), "interval") {
		t.Fatalf("expected lifetime rejection, got %v", err)
	}
}

func TestArtifactPlanAndProtectedArtifactValidation(t *testing.T) {
	directory := t.TempDir()
	plan := ArtifactPlan{
		PrivateKeyPath:       filepath.Join(directory, "node.key"),
		CertificateChainPath: filepath.Join(directory, "node-chain.pem"),
		RelayCAPath:          filepath.Join(directory, "relay-ca.pem"),
		OwnerUID:             uint32(os.Getuid()),
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("validate artifact plan: %v", err)
	}
	if err := os.WriteFile(plan.PrivateKeyPath, []byte("synthetic"), 0o600); err != nil {
		t.Fatalf("write temporary artifact: %v", err)
	}
	for _, path := range []string{plan.CertificateChainPath, plan.RelayCAPath} {
		if err := os.WriteFile(path, []byte("synthetic"), 0o600); err != nil {
			t.Fatalf("write temporary artifact: %v", err)
		}
	}
	if err := plan.ValidatePublished(); err != nil {
		t.Fatalf("validate published artifacts: %v", err)
	}
	if err := ValidateProtectedArtifact(plan.PrivateKeyPath, plan.OwnerUID); err != nil {
		t.Fatalf("validate protected artifact: %v", err)
	}
	if err := os.Chmod(plan.PrivateKeyPath, 0o640); err != nil {
		t.Fatalf("change temporary artifact mode: %v", err)
	}
	if err := ValidateProtectedArtifact(plan.PrivateKeyPath, plan.OwnerUID); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("expected mode rejection, got %v", err)
	}

	plan.RelayCAPath = plan.PrivateKeyPath
	if err := plan.Validate(); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("expected duplicate-path rejection, got %v", err)
	}
}

func issueNodeCertificate(
	t *testing.T,
	modify func(*x509.Certificate),
	leafSigner any,
) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test node client CA"},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("issue CA: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	var publicKey any
	if leafSigner == nil {
		leafKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			t.Fatalf("generate leaf key: %v", keyErr)
		}
		leafSigner = leafKey
		publicKey = &leafKey.PublicKey
	} else {
		switch key := leafSigner.(type) {
		case *rsa.PrivateKey:
			publicKey = &key.PublicKey
		case *ecdsa.PrivateKey:
			publicKey = &key.PublicKey
		default:
			t.Fatalf("unsupported test leaf signer %T", leafSigner)
		}
	}
	identityURI, err := InstallationURI(testInstallationID)
	if err != nil {
		t.Fatalf("build installation URI: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          new(big.Int).Lsh(big.NewInt(1), 127),
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{identityURI},
	}
	if modify != nil {
		modify(leafTemplate)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, publicKey, caKey)
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf, ca
}
