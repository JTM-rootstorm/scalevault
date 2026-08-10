package installations

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func TestValidateCSRAcceptsP256AndRejectsOtherProfiles(t *testing.T) {
	validDER, _ := makeCSR(t, elliptic.P256(), pkix.Name{CommonName: "ignored"}, nil, nil)
	validated, err := ValidateCSR(validDER)
	if err != nil || validated.PublicKey() == nil || validated.PublicKey().Curve != elliptic.P256() {
		t.Fatalf("validate P-256 CSR: %v", err)
	}

	p384DER, _ := makeCSR(t, elliptic.P384(), pkix.Name{}, nil, nil)
	invalid := [][]byte{
		nil,
		{0x30, 0x00},
		p384DER,
		append(append([]byte(nil), validDER...), 0x00),
		make([]byte, MaxCSRBytes+1),
	}
	for index, csr := range invalid {
		if _, err := ValidateCSR(csr); !errors.Is(err, ErrEnrollmentFailed) {
			t.Errorf("invalid CSR %d returned %v", index, err)
		}
	}
}

func TestCertificateIssuerIgnoresCallerIdentityAndProducesExactProfile(t *testing.T) {
	maliciousURI, err := url.Parse("spiffe://attacker/installation/not-authoritative")
	if err != nil {
		t.Fatalf("parse malicious URI: %v", err)
	}
	csrDER, _ := makeCSR(
		t,
		elliptic.P256(),
		pkix.Name{CommonName: "caller-controlled", Organization: []string{"caller"}},
		[]string{"attacker.invalid"},
		[]*url.URL{maliciousURI},
	)
	issuer := mustCertificateIssuer(t, testNow, bytes.Repeat([]byte{0x31}, 20), nil)
	issued, err := issuer.Issue(context.Background(), testTenantID, testInstallationID, csrDER, MaxCertificateLifetime)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	record := issued.Record()
	certificate, err := x509.ParseCertificate(issued.DER())
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	expectedURI := "spiffe://scalevault/installation/" + testInstallationID
	if certificate.Subject.String() != "" || len(certificate.DNSNames) != 0 ||
		len(certificate.URIs) != 1 || certificate.URIs[0].String() != expectedURI ||
		certificate.KeyUsage != x509.KeyUsageDigitalSignature || certificate.IsCA ||
		!certificate.BasicConstraintsValid || len(certificate.ExtKeyUsage) != 1 ||
		certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("issued certificate escaped exact profile: %#v", certificate)
	}
	if record.AuthorityURI != expectedURI || record.NotAfter.Sub(record.NotBefore) != MaxCertificateLifetime ||
		record.State != CertificateActive || record.Fingerprint != FingerprintDER(issued.DER()) {
		t.Fatalf("unexpected certificate record %v", record)
	}
	spki, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	if record.Fingerprint == CertificateFingerprint(sha256.Sum256(spki)) {
		t.Fatal("certificate fingerprint unexpectedly used SPKI instead of complete DER")
	}

	copyDER := issued.DER()
	copyDER[0] ^= 0xff
	if bytes.Equal(copyDER, issued.DER()) {
		t.Fatal("DER accessor returned mutable record storage")
	}
}

func TestCertificateIssuerRejectsSignerProfileDrift(t *testing.T) {
	csrDER, _ := makeCSR(t, elliptic.P256(), pkix.Name{}, nil, nil)
	mutations := []func(*x509.Certificate){
		func(template *x509.Certificate) { template.DNSNames = []string{"attacker.invalid"} },
		func(template *x509.Certificate) { template.Subject = pkix.Name{CommonName: "unexpected"} },
		func(template *x509.Certificate) {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		},
		func(template *x509.Certificate) { template.IsCA = true; template.KeyUsage |= x509.KeyUsageCertSign },
		func(template *x509.Certificate) { template.URIs = nil },
	}
	for index, mutation := range mutations {
		issuer := mustCertificateIssuer(t, testNow, bytes.Repeat([]byte{byte(index + 1)}, 20), mutation)
		if _, err := issuer.Issue(context.Background(), testTenantID, testInstallationID, csrDER, 24*time.Hour); !errors.Is(err, ErrEnrollmentFailed) {
			t.Errorf("profile mutation %d returned %v", index, err)
		}
	}

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong signer key: %v", err)
	}
	issuer := mustCertificateIssuer(t, testNow, bytes.Repeat([]byte{0x7f}, 20), nil)
	issuer.signer.(*testCertificateSigner).overridePublicKey = &wrongKey.PublicKey
	if _, err := issuer.Issue(context.Background(), testTenantID, testInstallationID, csrDER, time.Hour); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("wrong certificate public key returned %v", err)
	}
}

func TestCertificateIssuerRejectsInvalidLifetimeContextAndKey(t *testing.T) {
	csrDER, _ := makeCSR(t, elliptic.P256(), pkix.Name{}, nil, nil)
	issuer := mustCertificateIssuer(t, testNow, bytes.Repeat([]byte{0x11}, 20), nil)
	for _, lifetime := range []time.Duration{0, -time.Second, MaxCertificateLifetime + time.Second} {
		if _, err := issuer.Issue(context.Background(), testTenantID, testInstallationID, csrDER, lifetime); !errors.Is(err, ErrEnrollmentFailed) {
			t.Errorf("lifetime %s returned %v", lifetime, err)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := issuer.Issue(cancelled, testTenantID, testInstallationID, csrDER, time.Hour); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("cancelled context returned %v", err)
	}
	shortRandom := mustCertificateIssuer(t, testNow, make([]byte, 19), nil)
	if _, err := shortRandom.Issue(context.Background(), testTenantID, testInstallationID, csrDER, time.Hour); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("short serial entropy returned %v", err)
	}
}

type testCertificateSigner struct {
	issuer            *x509.Certificate
	key               *ecdsa.PrivateKey
	mutate            func(*x509.Certificate)
	overridePublicKey crypto.PublicKey
}

func (signer *testCertificateSigner) SignNodeCertificate(
	ctx context.Context,
	template *x509.Certificate,
	publicKey crypto.PublicKey,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	copyTemplate := *template
	copyTemplate.URIs = append([]*url.URL(nil), template.URIs...)
	copyTemplate.DNSNames = append([]string(nil), template.DNSNames...)
	copyTemplate.ExtKeyUsage = append([]x509.ExtKeyUsage(nil), template.ExtKeyUsage...)
	if signer.mutate != nil {
		signer.mutate(&copyTemplate)
	}
	if signer.overridePublicKey != nil {
		publicKey = signer.overridePublicKey
	}
	return x509.CreateCertificate(rand.Reader, &copyTemplate, signer.issuer, publicKey, signer.key)
}

func mustCertificateIssuer(
	t *testing.T,
	now time.Time,
	serialEntropy []byte,
	mutate func(*x509.Certificate),
) *NodeCertificateIssuer {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test enrollment CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create test CA: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse test CA: %v", err)
	}
	issuer, err := NewNodeCertificateIssuer(
		&testCertificateSigner{issuer: ca, key: caKey, mutate: mutate},
		bytes.NewReader(serialEntropy),
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("construct certificate issuer: %v", err)
	}
	return issuer
}

func makeCSR(
	t *testing.T,
	curve elliptic.Curve,
	subject pkix.Name,
	dnsNames []string,
	urls []*url.URL,
) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate CSR key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  subject,
		DNSNames: dnsNames,
		URIs:     urls,
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return der, key
}
