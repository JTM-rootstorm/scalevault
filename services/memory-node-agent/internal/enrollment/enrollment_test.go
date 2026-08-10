package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JTM-rootstorm/scalevault/services/memory-node-agent/internal/certificates"
)

const testInstallationID = "0197f2c1-7b2a-7abc-8def-0123456789ab"

var testNow = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

func TestNewRedemptionRequestAcceptsCanonicalTokenAndGeneratedCSR(t *testing.T) {
	material, err := certificates.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	token := base64.RawURLEncoding.EncodeToString(make([]byte, pairingTokenBytes))
	request, err := NewRedemptionRequest(token, material.CSRPEM)
	if err != nil {
		t.Fatalf("validate redemption request: %v", err)
	}
	if request.PairingToken != token || request.CSRPEM != string(material.CSRPEM) {
		t.Fatal("redemption request changed validated input")
	}
	for _, output := range []string{request.String(), fmt.Sprintf("%#v", request)} {
		if strings.Contains(output, token) {
			t.Fatal("formatted request disclosed pairing token")
		}
	}
}

func TestNewRedemptionRequestRejectsMalformedTokenAndCSR(t *testing.T) {
	material, err := certificates.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	for _, token := range []string{"short", strings.Repeat("A", 44), "not+base64url"} {
		if _, err := NewRedemptionRequest(token, material.CSRPEM); err == nil {
			t.Fatalf("expected malformed token rejection for length %d", len(token))
		}
	}
	validToken := base64.RawURLEncoding.EncodeToString(make([]byte, pairingTokenBytes))
	if _, err := NewRedemptionRequest(validToken, []byte("not a CSR")); err == nil {
		t.Fatal("expected malformed CSR rejection")
	}
}

func TestValidateResponseAcceptsSeparateClientChainAndRelayTrust(t *testing.T) {
	material, err := certificates.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	clientCA, clientCAKey := issueCA(t, "node client CA")
	relayCA, _ := issueCA(t, "relay server CA")
	leaf := issueLeaf(t, material.PrivateKey, clientCA, clientCAKey)
	response := RedemptionResponse{
		InstallationID:      testInstallationID,
		CertificateChainPEM: encodeCertificates(leaf, clientCA),
		RelayCAPEM:          encodeCertificates(relayCA),
	}

	validated, err := ValidateResponse(response, testInstallationID, &material.PrivateKey.PublicKey, testNow)
	if err != nil {
		t.Fatalf("validate response: %v", err)
	}
	if validated.InstallationID != testInstallationID || len(validated.CertificateChain) != 2 ||
		len(validated.RelayTrustAnchors) != 1 {
		t.Fatal("unexpected validated response shape")
	}
	if validated.LeafFingerprint != certificates.DERFingerprint(leaf.Raw) {
		t.Fatal("leaf fingerprint did not cover the complete DER certificate")
	}
}

func TestValidateResponseRejectsMalformedResponse(t *testing.T) {
	material, err := certificates.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	malformed := RedemptionResponse{
		InstallationID:      testInstallationID,
		CertificateChainPEM: "not PEM",
		RelayCAPEM:          "also not PEM",
	}
	if _, err := ValidateResponse(malformed, testInstallationID, &material.PrivateKey.PublicKey, testNow); err == nil ||
		!strings.Contains(err.Error(), "malformed") {
		t.Fatalf("expected malformed response rejection, got %v", err)
	}
}

func TestValidateResponseRejectsInstallationAndKeyMismatch(t *testing.T) {
	material, err := certificates.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	clientCA, clientCAKey := issueCA(t, "node client CA")
	relayCA, _ := issueCA(t, "relay server CA")
	leaf := issueLeaf(t, material.PrivateKey, clientCA, clientCAKey)
	response := RedemptionResponse{
		InstallationID:      testInstallationID,
		CertificateChainPEM: encodeCertificates(leaf, clientCA),
		RelayCAPEM:          encodeCertificates(relayCA),
	}
	if _, err := ValidateResponse(response, "0197f2c1-7b2a-7abc-8def-0123456789ac", &material.PrivateKey.PublicKey, testNow); err == nil ||
		!strings.Contains(err.Error(), "installation mismatch") {
		t.Fatalf("expected installation mismatch, got %v", err)
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	if _, err := ValidateResponse(response, testInstallationID, &otherKey.PublicKey, testNow); err == nil ||
		!strings.Contains(err.Error(), "key mismatch") {
		t.Fatalf("expected key mismatch, got %v", err)
	}
}

func issueCA(t *testing.T, commonName string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("issue CA: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return certificate, key
}

func issueLeaf(
	t *testing.T,
	key *ecdsa.PrivateKey,
	issuer *x509.Certificate,
	issuerKey *ecdsa.PrivateKey,
) *x509.Certificate {
	t.Helper()
	identityURI, err := certificates.InstallationURI(testInstallationID)
	if err != nil {
		t.Fatalf("build installation URI: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          new(big.Int).Lsh(big.NewInt(1), 127),
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{identityURI},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return certificate
}

func encodeCertificates(values ...*x509.Certificate) string {
	var encoded strings.Builder
	for _, certificate := range values {
		encoded.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
	}
	return encoded.String()
}
