package installations

import (
	"context"
	"errors"
	"time"
)

// ErrEnrollmentFailed is the single public-safe failure for enrollment,
// certificate, identity mismatch, expiry, replay, and revocation failures.
var ErrEnrollmentFailed = errors.New("enrollment failed")

// PairingRedemption is committed atomically by Store after certificate signing.
// A store must recheck the pairing record and all identity/time fields while
// consuming the code and inserting the certificate in one transaction.
type PairingRedemption struct {
	Verifier       PairingVerifier
	TenantID       string
	InstallationID string
	RedeemedAt     time.Time
	Certificate    CertificateRecord
}

// CertificateRotation atomically activates a replacement while bounding the
// prior certificate's overlap.
type CertificateRotation struct {
	TenantID           string
	InstallationID     string
	CurrentFingerprint CertificateFingerprint
	Replacement        CertificateRecord
	RotatedAt          time.Time
	Overlap            time.Duration
}

// Store is the persistence boundary for relay installation lifecycle state.
// RedeemPairing and RotateCertificate must be atomic in every implementation.
type Store interface {
	CreatePairing(context.Context, PairingRecord) error
	FindPairing(context.Context, PairingVerifier, time.Time) (PairingRecord, error)
	RedeemPairing(context.Context, PairingRedemption) error
	RotateCertificate(context.Context, CertificateRotation) error
	RevokeCertificate(context.Context, string, string, CertificateFingerprint, time.Time) error
	RevokeInstallation(context.Context, string, string, time.Time) error
	CertificateActive(context.Context, string, string, CertificateFingerprint, time.Time) (bool, error)
}

func validUUID7(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' ||
		value[23] != '-' || value[14] != '7' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return value[19] == '8' || value[19] == '9' || value[19] == 'a' || value[19] == 'b'
}
