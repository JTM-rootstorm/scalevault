package installations

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net/url"
	"time"
)

const (
	// MaxCSRBytes bounds unauthenticated enrollment input before ASN.1 parsing.
	MaxCSRBytes = 16 * 1024
	// MaxCertificateBytes bounds signer output before certificate parsing.
	MaxCertificateBytes = 16 * 1024
	// MaxCertificateLifetime is the v1 node-certificate profile maximum.
	MaxCertificateLifetime = 30 * 24 * time.Hour
	// RotationDefaultLead is when an ordinary certificate rotation begins.
	RotationDefaultLead = 7 * 24 * time.Hour
	// RotationMaxOverlap is the maximum time both certificates may remain active.
	RotationMaxOverlap = 24 * time.Hour
)

// CertificateFingerprint is SHA-256 over the complete DER certificate.
type CertificateFingerprint [sha256.Size]byte

// CertificateState is the closed lifecycle of a node certificate.
type CertificateState string

const (
	CertificateActive   CertificateState = "active"
	CertificateRetiring CertificateState = "retiring"
	CertificateRevoked  CertificateState = "revoked"
)

// ValidatedCSR retains only the verified public key. Caller-provided subject
// fields and requested extensions are deliberately not exposed to issuance.
type ValidatedCSR struct {
	publicKey *ecdsa.PublicKey
}

// PublicKey returns a defensive copy of the verified P-256 public key.
func (csr ValidatedCSR) PublicKey() *ecdsa.PublicKey {
	if csr.publicKey == nil {
		return nil
	}
	return &ecdsa.PublicKey{
		Curve: csr.publicKey.Curve,
		X:     new(big.Int).Set(csr.publicKey.X),
		Y:     new(big.Int).Set(csr.publicKey.Y),
	}
}

// ValidateCSR accepts one bounded DER PKCS #10 request containing a valid
// ECDSA P-256 key and signature. Subjects and requested SANs are ignored.
func ValidateCSR(der []byte) (ValidatedCSR, error) {
	if len(der) == 0 || len(der) > MaxCSRBytes {
		return ValidatedCSR{}, ErrEnrollmentFailed
	}
	request, err := x509.ParseCertificateRequest(der)
	if err != nil || request.CheckSignature() != nil {
		return ValidatedCSR{}, ErrEnrollmentFailed
	}
	publicKey, ok := request.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() || publicKey.X == nil || publicKey.Y == nil ||
		!publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return ValidatedCSR{}, ErrEnrollmentFailed
	}
	return ValidatedCSR{publicKey: &ecdsa.PublicKey{
		Curve: publicKey.Curve,
		X:     new(big.Int).Set(publicKey.X),
		Y:     new(big.Int).Set(publicKey.Y),
	}}, nil
}

// CertificateSigner is the isolated CA boundary. Implementations must sign the
// supplied server-owned template and public key without adding identities.
type CertificateSigner interface {
	SignNodeCertificate(context.Context, *x509.Certificate, crypto.PublicKey) ([]byte, error)
}

// CertificateRecord is the public, payload-free node certificate index state.
type CertificateRecord struct {
	TenantID       string
	InstallationID string
	Fingerprint    CertificateFingerprint
	SerialHex      string
	AuthorityURI   string
	NotBefore      time.Time
	NotAfter       time.Time
	State          CertificateState
	CreatedAt      time.Time
	RetireAt       time.Time
	RevokedAt      time.Time
}

// String avoids logging the installation's certificate identity through
// annotated object formats.
func (CertificateRecord) String() string { return "CertificateRecord(<redacted>)" }

// GoString avoids expanded certificate object logs.
func (CertificateRecord) GoString() string { return "CertificateRecord(<redacted>)" }

// IssuedCertificate is the transient enrollment issuance result. Its DER is only
// returned to the enrollment client; the persisted Record contains metadata.
type IssuedCertificate struct {
	der    []byte
	record CertificateRecord
}

// String prevents certificate material from entering ordinary logs.
func (IssuedCertificate) String() string { return "IssuedCertificate(<redacted>)" }

// GoString prevents expanded certificate material logs.
func (IssuedCertificate) GoString() string { return "IssuedCertificate(<redacted>)" }

// DER returns the public certificate as a defensive copy.
func (issued IssuedCertificate) DER() []byte { return append([]byte(nil), issued.der...) }

// Record returns the metadata-only certificate state accepted by Store.
func (issued IssuedCertificate) Record() CertificateRecord { return issued.record }

// ActiveAt reports whether the certificate is eligible before installation-
// level revocation is applied by the Store.
func (record CertificateRecord) ActiveAt(now time.Time) bool {
	now = now.UTC()
	if now.Before(record.NotBefore) || !now.Before(record.NotAfter) || !record.RevokedAt.IsZero() {
		return false
	}
	switch record.State {
	case CertificateActive:
		return true
	case CertificateRetiring:
		return !record.RetireAt.IsZero() && now.Before(record.RetireAt)
	default:
		return false
	}
}

// NodeCertificateIssuer creates and validates the authoritative v1 node
// certificate profile using injected time, entropy, and CA signing behavior.
type NodeCertificateIssuer struct {
	signer CertificateSigner
	random io.Reader
	clock  func() time.Time
}

// NewNodeCertificateIssuer constructs the certificate profile issuer.
func NewNodeCertificateIssuer(signer CertificateSigner, random io.Reader, clock func() time.Time) (*NodeCertificateIssuer, error) {
	if signer == nil || random == nil || clock == nil {
		return nil, ErrEnrollmentFailed
	}
	return &NodeCertificateIssuer{signer: signer, random: random, clock: clock}, nil
}

// Issue validates the CSR, creates a server-owned identity template, delegates
// signing, and validates the resulting DER against the exact profile.
func (issuer *NodeCertificateIssuer) Issue(
	ctx context.Context,
	tenantID string,
	installationID string,
	csrDER []byte,
	lifetime time.Duration,
) (IssuedCertificate, error) {
	if issuer == nil || !validUUID7(tenantID) || !validUUID7(installationID) ||
		lifetime <= 0 || lifetime > MaxCertificateLifetime || ctx == nil || ctx.Err() != nil {
		return IssuedCertificate{}, ErrEnrollmentFailed
	}
	csr, err := ValidateCSR(csrDER)
	if err != nil {
		return IssuedCertificate{}, ErrEnrollmentFailed
	}
	serial, err := issuer.serialNumber()
	if err != nil {
		return IssuedCertificate{}, ErrEnrollmentFailed
	}
	now := issuer.clock().UTC().Truncate(time.Second)
	if now.IsZero() {
		return IssuedCertificate{}, ErrEnrollmentFailed
	}
	authorityURI, err := installationURI(installationID)
	if err != nil {
		return IssuedCertificate{}, ErrEnrollmentFailed
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{},
		NotBefore:             now,
		NotAfter:              now.Add(lifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{authorityURI},
	}
	// Keep the template free of caller-controlled CSR fields. The apparently
	// redundant local copy also prevents a signer from mutating expected values.
	expected := certificateExpectation{
		serial:       new(big.Int).Set(serial),
		notBefore:    template.NotBefore,
		notAfter:     template.NotAfter,
		authorityURI: authorityURI.String(),
		publicKey:    csr.PublicKey(),
	}
	der, err := issuer.signer.SignNodeCertificate(ctx, template, csr.PublicKey())
	if err != nil || len(der) == 0 || len(der) > MaxCertificateBytes {
		return IssuedCertificate{}, ErrEnrollmentFailed
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil || validateIssuedCertificate(certificate, expected) != nil {
		return IssuedCertificate{}, ErrEnrollmentFailed
	}
	return IssuedCertificate{
		der: append([]byte(nil), der...),
		record: CertificateRecord{
			TenantID:       tenantID,
			InstallationID: installationID,
			Fingerprint:    FingerprintDER(der),
			SerialHex:      hex.EncodeToString(serial.Bytes()),
			AuthorityURI:   authorityURI.String(),
			NotBefore:      certificate.NotBefore.UTC(),
			NotAfter:       certificate.NotAfter.UTC(),
			State:          CertificateActive,
			CreatedAt:      now,
		},
	}, nil
}

func (issuer *NodeCertificateIssuer) serialNumber() (*big.Int, error) {
	serialBytes := make([]byte, 20)
	if _, err := io.ReadFull(issuer.random, serialBytes); err != nil {
		return nil, err
	}
	serialBytes[0] &= 0x7f
	serialBytes[0] |= 0x40
	return new(big.Int).SetBytes(serialBytes), nil
}

type certificateExpectation struct {
	serial       *big.Int
	notBefore    time.Time
	notAfter     time.Time
	authorityURI string
	publicKey    *ecdsa.PublicKey
}

func validateIssuedCertificate(certificate *x509.Certificate, expected certificateExpectation) error {
	if certificate == nil || certificate.SerialNumber == nil ||
		certificate.SerialNumber.Sign() <= 0 ||
		certificate.SerialNumber.Cmp(expected.serial) != 0 ||
		!certificate.NotBefore.Equal(expected.notBefore) ||
		!certificate.NotAfter.Equal(expected.notAfter) ||
		certificate.KeyUsage != x509.KeyUsageDigitalSignature ||
		!certificate.BasicConstraintsValid || certificate.IsCA ||
		len(certificate.ExtKeyUsage) != 1 ||
		certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		len(certificate.UnknownExtKeyUsage) != 0 ||
		len(certificate.DNSNames) != 0 || len(certificate.EmailAddresses) != 0 ||
		len(certificate.IPAddresses) != 0 ||
		len(certificate.UnhandledCriticalExtensions) != 0 ||
		len(certificate.Subject.Names) != 0 || len(certificate.Subject.ExtraNames) != 0 ||
		len(certificate.URIs) != 1 || certificate.URIs[0].String() != expected.authorityURI {
		return ErrEnrollmentFailed
	}
	actualKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || actualKey.Curve != elliptic.P256() || expected.publicKey == nil {
		return ErrEnrollmentFailed
	}
	expectedDER, err := x509.MarshalPKIXPublicKey(expected.publicKey)
	if err != nil {
		return ErrEnrollmentFailed
	}
	actualDER, err := x509.MarshalPKIXPublicKey(actualKey)
	if err != nil || !bytes.Equal(actualDER, expectedDER) {
		return ErrEnrollmentFailed
	}
	return nil
}

// FingerprintDER returns SHA-256 over the complete certificate DER.
func FingerprintDER(der []byte) CertificateFingerprint { return sha256.Sum256(der) }

func installationURI(installationID string) (*url.URL, error) {
	if !validUUID7(installationID) {
		return nil, ErrEnrollmentFailed
	}
	return url.Parse("spiffe://scalevault/installation/" + installationID)
}
