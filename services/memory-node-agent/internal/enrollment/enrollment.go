// Package enrollment validates node-agent enrollment exchanges without owning transport.
package enrollment

import (
	"crypto/ecdsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/JTM-rootstorm/scalevault/services/memory-node-agent/internal/certificates"
)

const pairingTokenBytes = 32

// RedemptionRequest is the validated content needed by an enrollment transport.
// Its field names are not a frozen public wire contract.
type RedemptionRequest struct {
	PairingToken string
	CSRPEM       string
}

// String prevents accidental logging of the one-use pairing token.
func (RedemptionRequest) String() string {
	return "RedemptionRequest{pairing_token=<redacted>,csr=<omitted>}"
}

// GoString also redacts debug formatting such as %#v.
func (RedemptionRequest) GoString() string {
	return "RedemptionRequest{pairing_token=<redacted>,csr=<omitted>}"
}

// NewRedemptionRequest validates the one-use token and request-neutral P-256 CSR.
func NewRedemptionRequest(pairingToken string, csrPEM []byte) (RedemptionRequest, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(pairingToken)
	if err != nil || len(decoded) != pairingTokenBytes ||
		subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(decoded)), []byte(pairingToken)) != 1 {
		return RedemptionRequest{}, errors.New("pairing token is malformed")
	}
	if _, err := certificates.ParseAndValidateCSR(csrPEM); err != nil {
		return RedemptionRequest{}, err
	}
	return RedemptionRequest{PairingToken: pairingToken, CSRPEM: string(csrPEM)}, nil
}

// RedemptionResponse is the content returned after a pairing code is consumed.
// The issuing client chain and relay server trust bundle are deliberately separate.
type RedemptionResponse struct {
	InstallationID      string
	CertificateChainPEM string
	RelayCAPEM          string
}

// ValidatedResponse contains parsed public material ready for protected publication.
type ValidatedResponse struct {
	InstallationID    string
	CertificateChain  []*x509.Certificate
	RelayTrustAnchors []*x509.Certificate
	LeafFingerprint   [32]byte
}

// ValidateResponse verifies shape, installation identity, key possession,
// certificate profile, chain signatures, and relay trust-anchor shape.
func ValidateResponse(
	response RedemptionResponse,
	expectedInstallationID string,
	expectedPublicKey *ecdsa.PublicKey,
	now time.Time,
) (ValidatedResponse, error) {
	if response.InstallationID != expectedInstallationID {
		return ValidatedResponse{}, errors.New("enrollment response installation mismatch")
	}
	if expectedPublicKey == nil {
		return ValidatedResponse{}, errors.New("expected node public key is required")
	}
	chain, err := parseCertificatePEM(response.CertificateChainPEM)
	if err != nil || len(chain) < 2 {
		return ValidatedResponse{}, errors.New("enrollment response certificate chain is malformed")
	}
	anchors, err := parseCertificatePEM(response.RelayCAPEM)
	if err != nil || len(anchors) == 0 {
		return ValidatedResponse{}, errors.New("enrollment response relay CA bundle is malformed")
	}

	leaf := chain[0]
	if err := certificates.VerifyProfile(leaf, expectedInstallationID, now); err != nil {
		return ValidatedResponse{}, err
	}
	leafKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !leafKey.Equal(expectedPublicKey) {
		return ValidatedResponse{}, errors.New("enrollment response certificate key mismatch")
	}
	for index := 1; index < len(chain); index++ {
		issuer := chain[index]
		if !issuer.BasicConstraintsValid || !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
			return ValidatedResponse{}, errors.New("enrollment response client chain contains an invalid issuer")
		}
		if err := chain[index-1].CheckSignatureFrom(issuer); err != nil {
			return ValidatedResponse{}, errors.New("enrollment response client chain signature is invalid")
		}
	}
	for _, anchor := range anchors {
		if !anchor.BasicConstraintsValid || !anchor.IsCA || anchor.KeyUsage&x509.KeyUsageCertSign == 0 {
			return ValidatedResponse{}, errors.New("enrollment response relay trust anchor is invalid")
		}
		if now.Before(anchor.NotBefore) || !now.Before(anchor.NotAfter) {
			return ValidatedResponse{}, errors.New("enrollment response relay trust anchor is not currently valid")
		}
	}

	return ValidatedResponse{
		InstallationID:    response.InstallationID,
		CertificateChain:  chain,
		RelayTrustAnchors: anchors,
		LeafFingerprint:   certificates.DERFingerprint(leaf.Raw),
	}, nil
}

func parseCertificatePEM(value string) ([]*x509.Certificate, error) {
	remaining := []byte(value)
	var parsed []*x509.Certificate
	for len(strings.TrimSpace(string(remaining))) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("certificate PEM is malformed")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("certificate DER is malformed")
		}
		parsed = append(parsed, certificate)
		remaining = rest
	}
	if len(parsed) == 0 {
		return nil, errors.New("certificate PEM is empty")
	}
	return parsed, nil
}
