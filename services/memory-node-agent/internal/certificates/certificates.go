// Package certificates creates and validates node-agent certificate material.
package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	maximumCertificateLifetime = 30 * 24 * time.Hour
	protectedArtifactMode      = fs.FileMode(0o600)
)

// IdentityMaterial contains a locally generated private key and request-neutral CSR.
// The private key must never be printed or transmitted.
type IdentityMaterial struct {
	PrivateKey    *ecdsa.PrivateKey
	PrivateKeyPEM []byte
	CSRDER        []byte
	CSRPEM        []byte
}

// String deliberately prevents ordinary formatting from disclosing key material.
func (IdentityMaterial) String() string {
	return "IdentityMaterial{private_key=<redacted>,csr=<omitted>}"
}

// GoString also redacts debug formatting such as %#v.
func (IdentityMaterial) GoString() string {
	return "IdentityMaterial{private_key=<redacted>,csr=<omitted>}"
}

// GenerateIdentity creates a P-256 key and a signed CSR with no caller-controlled
// subject or SAN. The relay assigns certificate identity from its installation record.
func GenerateIdentity() (IdentityMaterial, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return IdentityMaterial{}, fmt.Errorf("generate node private key: %w", err)
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return IdentityMaterial{}, fmt.Errorf("encode node private key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, privateKey)
	if err != nil {
		return IdentityMaterial{}, fmt.Errorf("create node certificate request: %w", err)
	}

	return IdentityMaterial{
		PrivateKey: privateKey,
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateDER,
		}),
		CSRDER: append([]byte(nil), csrDER...),
		CSRPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrDER,
		}),
	}, nil
}

// ParseAndValidateCSR accepts one PEM-encoded, self-signed P-256 CSR. Subjects,
// SANs, and extensions are rejected so a node request cannot suggest authority.
func ParseAndValidateCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("certificate request must contain exactly one CSR PEM block")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, errors.New("certificate request is malformed")
	}
	if err := request.CheckSignature(); err != nil {
		return nil, errors.New("certificate request signature is invalid")
	}
	publicKey, ok := request.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, errors.New("certificate request must use ECDSA P-256")
	}
	if request.Subject.String() != "" {
		return nil, errors.New("certificate request subject must be empty")
	}
	if len(request.DNSNames) != 0 || len(request.EmailAddresses) != 0 ||
		len(request.IPAddresses) != 0 || len(request.URIs) != 0 ||
		len(request.Extensions) != 0 || len(request.ExtraExtensions) != 0 {
		return nil, errors.New("certificate request extensions and SANs must be empty")
	}
	return request, nil
}

// InstallationURI returns the sole URI SAN permitted on a node certificate.
func InstallationURI(installationID string) (*url.URL, error) {
	if !validLowercaseUUIDv7(installationID) {
		return nil, errors.New("installation ID must be a lowercase UUIDv7")
	}
	return url.Parse("spiffe://scalevault/installation/" + installationID)
}

func validLowercaseUUIDv7(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return value[14] == '7' && strings.ContainsRune("89ab", rune(value[19]))
}

// DERFingerprint returns the SHA-256 identity of the complete DER certificate.
func DERFingerprint(certificateDER []byte) [sha256.Size]byte {
	return sha256.Sum256(certificateDER)
}

// FingerprintHex renders a DER fingerprint only when an operator explicitly
// needs the non-secret certificate identity; callers must not put it in logs.
func FingerprintHex(fingerprint [sha256.Size]byte) string {
	return hex.EncodeToString(fingerprint[:])
}

// VerifyProfile enforces the complete ADR 0020 node-client certificate profile.
func VerifyProfile(certificate *x509.Certificate, installationID string, now time.Time) error {
	if certificate == nil {
		return errors.New("node certificate is required")
	}
	expectedURI, err := InstallationURI(installationID)
	if err != nil {
		return err
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return errors.New("node certificate must use ECDSA P-256")
	}
	if !certificate.BasicConstraintsValid || certificate.IsCA {
		return errors.New("node certificate must have a CA=false basic constraint")
	}
	if certificate.SerialNumber == nil || certificate.SerialNumber.Sign() <= 0 || certificate.SerialNumber.BitLen() < 128 {
		return errors.New("node certificate serial must be a positive value of at least 128 bits")
	}
	if certificate.KeyUsage != x509.KeyUsageDigitalSignature {
		return errors.New("node certificate key usage must be exactly digitalSignature")
	}
	if len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		len(certificate.UnknownExtKeyUsage) != 0 {
		return errors.New("node certificate EKU must be exactly clientAuth")
	}
	if len(certificate.UnhandledCriticalExtensions) != 0 {
		return errors.New("node certificate has an unknown critical extension")
	}
	if len(certificate.DNSNames) != 0 || len(certificate.EmailAddresses) != 0 ||
		len(certificate.IPAddresses) != 0 {
		return errors.New("node certificate must not contain DNS, email, or IP SANs")
	}
	if len(certificate.URIs) != 1 || certificate.URIs[0].String() != expectedURI.String() {
		return errors.New("node certificate must contain exactly the expected installation URI SAN")
	}
	if !certificate.NotAfter.After(certificate.NotBefore) ||
		certificate.NotAfter.Sub(certificate.NotBefore) > maximumCertificateLifetime {
		return errors.New("node certificate validity interval is invalid")
	}
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return errors.New("node certificate is not currently valid")
	}
	return nil
}

// ArtifactPlan describes the protected files an operator CLI must publish. It
// intentionally contains paths and invariants only, never credential bytes.
type ArtifactPlan struct {
	PrivateKeyPath       string
	CertificateChainPath string
	RelayCAPath          string
	OwnerUID             uint32
}

// Validate checks that all final destinations are absolute, clean, distinct,
// and colocated so a privileged caller can apply one protected-directory policy.
func (plan ArtifactPlan) Validate() error {
	paths := []string{plan.PrivateKeyPath, plan.CertificateChainPath, plan.RelayCAPath}
	seen := make(map[string]struct{}, len(paths))
	var directory string
	for _, path := range paths {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("artifact paths must be non-empty, absolute, and clean")
		}
		if filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
			return errors.New("artifact paths must name files")
		}
		if _, exists := seen[path]; exists {
			return errors.New("artifact paths must be distinct")
		}
		seen[path] = struct{}{}
		if directory == "" {
			directory = filepath.Dir(path)
		} else if filepath.Dir(path) != directory {
			return errors.New("artifact paths must share one protected directory")
		}
	}
	return nil
}

// ValidatePublished checks every artifact in the plan after a privileged caller
// has atomically published it. The method never handles or inspects file contents.
func (plan ArtifactPlan) ValidatePublished() error {
	if err := plan.Validate(); err != nil {
		return err
	}
	for _, path := range []string{plan.PrivateKeyPath, plan.CertificateChainPath, plan.RelayCAPath} {
		if err := ValidateProtectedArtifact(path, plan.OwnerUID); err != nil {
			return err
		}
	}
	return nil
}

// ValidateProtectedArtifact verifies an already-published single-link regular
// file. Lstat rejects symlinks; callers should pass UID 0 from the root CLI.
func ValidateProtectedArtifact(path string, expectedUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect protected artifact: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("protected artifact must be a regular file")
	}
	if info.Mode().Perm() != protectedArtifactMode {
		return errors.New("protected artifact mode must be 0600")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("protected artifact ownership metadata is unavailable")
	}
	if stat.Uid != expectedUID {
		return errors.New("protected artifact owner is incorrect")
	}
	if stat.Nlink != 1 {
		return errors.New("protected artifact must have exactly one link")
	}
	return nil
}
