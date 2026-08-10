package installations

import (
	"context"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/hex"
	"sync"
	"time"
)

// MemoryStore is a process-local reference implementation of Store. It exists
// for domain composition and tests; production enrollment uses PostgreSQL.
type MemoryStore struct {
	mu                    sync.Mutex
	pairings              map[PairingVerifier]PairingRecord
	certificates          map[CertificateFingerprint]CertificateRecord
	installationRevokedAt map[installationKey]time.Time
}

type installationKey struct {
	tenantID       string
	installationID string
}

// NewMemoryStore returns an empty atomic in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		pairings:              make(map[PairingVerifier]PairingRecord),
		certificates:          make(map[CertificateFingerprint]CertificateRecord),
		installationRevokedAt: make(map[installationKey]time.Time),
	}
}

// CreatePairing inserts one pending, bounded pairing record.
func (store *MemoryStore) CreatePairing(ctx context.Context, record PairingRecord) error {
	if contextFailed(ctx) || !validPairingRecord(record) {
		return ErrEnrollmentFailed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.pairings[record.Verifier]; exists {
		return ErrEnrollmentFailed
	}
	if _, revoked := store.installationRevokedAt[key(record.TenantID, record.InstallationID)]; revoked {
		return ErrEnrollmentFailed
	}
	store.pairings[record.Verifier] = record
	return nil
}

// FindPairing retrieves secret-free state for CSR signing. It is not authority:
// RedeemPairing rechecks all state atomically afterward.
func (store *MemoryStore) FindPairing(
	ctx context.Context,
	verifier PairingVerifier,
	observedAt time.Time,
) (PairingRecord, error) {
	if contextFailed(ctx) || observedAt.IsZero() {
		return PairingRecord{}, ErrEnrollmentFailed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.pairings[verifier]
	storedVerifier := PairingVerifier{}
	if exists {
		storedVerifier = record.Verifier
	}
	verifierMatches := hmac.Equal(storedVerifier[:], verifier[:])
	if !exists || !verifierMatches || record.State != PairingPending || observedAt.Before(record.CreatedAt) ||
		!observedAt.Before(record.ExpiresAt) {
		return PairingRecord{}, ErrEnrollmentFailed
	}
	return record, nil
}

// RedeemPairing atomically consumes one current pairing and inserts exactly one
// matching certificate record.
func (store *MemoryStore) RedeemPairing(ctx context.Context, redemption PairingRedemption) error {
	if contextFailed(ctx) || !validUUID7(redemption.TenantID) ||
		!validUUID7(redemption.InstallationID) || redemption.RedeemedAt.IsZero() ||
		!validCertificateRecord(redemption.Certificate) {
		return ErrEnrollmentFailed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.pairings[redemption.Verifier]
	storedVerifier := PairingVerifier{}
	if exists {
		storedVerifier = record.Verifier
	}
	verifierMatches := hmac.Equal(storedVerifier[:], redemption.Verifier[:])
	if !exists || !verifierMatches || record.State != PairingPending ||
		!sameIdentifier(record.TenantID, redemption.TenantID) ||
		!sameIdentifier(record.InstallationID, redemption.InstallationID) ||
		!sameIdentifier(redemption.Certificate.TenantID, redemption.TenantID) ||
		!sameIdentifier(redemption.Certificate.InstallationID, redemption.InstallationID) ||
		redemption.RedeemedAt.Before(record.CreatedAt) ||
		!redemption.RedeemedAt.Before(record.ExpiresAt) ||
		!redemption.Certificate.ActiveAt(redemption.RedeemedAt) {
		return ErrEnrollmentFailed
	}
	installation := key(redemption.TenantID, redemption.InstallationID)
	if _, revoked := store.installationRevokedAt[installation]; revoked ||
		store.hasActiveCertificateLocked(installation, redemption.RedeemedAt) {
		return ErrEnrollmentFailed
	}
	if _, exists := store.certificates[redemption.Certificate.Fingerprint]; exists {
		return ErrEnrollmentFailed
	}
	if store.hasSerialLocked(redemption.Certificate) {
		return ErrEnrollmentFailed
	}
	record.State = PairingConsumed
	record.ConsumedAt = redemption.RedeemedAt.UTC()
	store.pairings[redemption.Verifier] = record
	store.certificates[redemption.Certificate.Fingerprint] = redemption.Certificate
	return nil
}

// RotateCertificate atomically retires the current certificate and activates
// one same-installation replacement for a bounded overlap.
func (store *MemoryStore) RotateCertificate(ctx context.Context, rotation CertificateRotation) error {
	if contextFailed(ctx) || !validUUID7(rotation.TenantID) ||
		!validUUID7(rotation.InstallationID) || rotation.RotatedAt.IsZero() ||
		rotation.Overlap <= 0 || rotation.Overlap > RotationMaxOverlap ||
		!validCertificateRecord(rotation.Replacement) {
		return ErrEnrollmentFailed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	installation := key(rotation.TenantID, rotation.InstallationID)
	if _, revoked := store.installationRevokedAt[installation]; revoked {
		return ErrEnrollmentFailed
	}
	current, exists := store.certificates[rotation.CurrentFingerprint]
	retireAt := rotation.RotatedAt.UTC().Add(rotation.Overlap)
	if !exists || current.State != CertificateActive ||
		!sameCertificateInstallation(current, rotation.TenantID, rotation.InstallationID) ||
		!current.ActiveAt(rotation.RotatedAt) ||
		rotation.RotatedAt.Before(current.NotAfter.Add(-RotationDefaultLead)) ||
		!sameCertificateInstallation(rotation.Replacement, rotation.TenantID, rotation.InstallationID) ||
		!rotation.Replacement.ActiveAt(rotation.RotatedAt) ||
		!retireAt.Before(current.NotAfter) ||
		rotation.Replacement.Fingerprint == rotation.CurrentFingerprint {
		return ErrEnrollmentFailed
	}
	if _, exists := store.certificates[rotation.Replacement.Fingerprint]; exists {
		return ErrEnrollmentFailed
	}
	if store.hasSerialLocked(rotation.Replacement) {
		return ErrEnrollmentFailed
	}
	current.State = CertificateRetiring
	current.RetireAt = retireAt
	store.certificates[rotation.CurrentFingerprint] = current
	store.certificates[rotation.Replacement.Fingerprint] = rotation.Replacement
	return nil
}

// RevokeCertificate idempotently makes one certificate unusable.
func (store *MemoryStore) RevokeCertificate(
	ctx context.Context,
	tenantID string,
	installationID string,
	fingerprint CertificateFingerprint,
	revokedAt time.Time,
) error {
	if contextFailed(ctx) || !validUUID7(tenantID) || !validUUID7(installationID) || revokedAt.IsZero() {
		return ErrEnrollmentFailed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.certificates[fingerprint]
	if !exists || !sameCertificateInstallation(record, tenantID, installationID) ||
		revokedAt.Before(record.CreatedAt) {
		return ErrEnrollmentFailed
	}
	if record.State == CertificateRevoked {
		return nil
	}
	record.State = CertificateRevoked
	record.RevokedAt = revokedAt.UTC()
	store.certificates[fingerprint] = record
	return nil
}

// RevokeInstallation idempotently revokes the installation and every current
// or future certificate lookup. Revocation is deliberately irreversible.
func (store *MemoryStore) RevokeInstallation(
	ctx context.Context,
	tenantID string,
	installationID string,
	revokedAt time.Time,
) error {
	if contextFailed(ctx) || !validUUID7(tenantID) || !validUUID7(installationID) || revokedAt.IsZero() {
		return ErrEnrollmentFailed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	installation := key(tenantID, installationID)
	if _, exists := store.installationRevokedAt[installation]; exists {
		return nil
	}
	for _, record := range store.certificates {
		if sameCertificateInstallation(record, tenantID, installationID) && revokedAt.Before(record.CreatedAt) {
			return ErrEnrollmentFailed
		}
	}
	store.installationRevokedAt[installation] = revokedAt.UTC()
	for fingerprint, record := range store.certificates {
		if sameCertificateInstallation(record, tenantID, installationID) &&
			record.State != CertificateRevoked {
			record.State = CertificateRevoked
			record.RevokedAt = revokedAt.UTC()
			store.certificates[fingerprint] = record
		}
	}
	return nil
}

// CertificateActive performs the certificate, identity, time, and installation
// revocation check used before accepting an mTLS connection.
func (store *MemoryStore) CertificateActive(
	ctx context.Context,
	tenantID string,
	installationID string,
	fingerprint CertificateFingerprint,
	now time.Time,
) (bool, error) {
	if contextFailed(ctx) || !validUUID7(tenantID) || !validUUID7(installationID) || now.IsZero() {
		return false, ErrEnrollmentFailed
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, revoked := store.installationRevokedAt[key(tenantID, installationID)]; revoked {
		return false, nil
	}
	record, exists := store.certificates[fingerprint]
	if !exists || !sameCertificateInstallation(record, tenantID, installationID) {
		return false, nil
	}
	return record.ActiveAt(now), nil
}

func (store *MemoryStore) hasActiveCertificateLocked(installation installationKey, now time.Time) bool {
	for _, certificate := range store.certificates {
		if sameIdentifier(certificate.TenantID, installation.tenantID) &&
			sameIdentifier(certificate.InstallationID, installation.installationID) &&
			certificate.ActiveAt(now) {
			return true
		}
	}
	return false
}

func (store *MemoryStore) hasSerialLocked(candidate CertificateRecord) bool {
	for _, certificate := range store.certificates {
		if certificate.SerialHex == candidate.SerialHex {
			return true
		}
	}
	return false
}

func validPairingRecord(record PairingRecord) bool {
	return record.Verifier != (PairingVerifier{}) && validUUID7(record.TenantID) && validUUID7(record.InstallationID) &&
		record.State == PairingPending && record.ConsumedAt.IsZero() &&
		!record.CreatedAt.IsZero() && record.ExpiresAt.After(record.CreatedAt) &&
		record.ExpiresAt.Sub(record.CreatedAt) <= MaxPairingLifetime
}

func validCertificateRecord(record CertificateRecord) bool {
	serial, serialErr := hex.DecodeString(record.SerialHex)
	if record.Fingerprint == (CertificateFingerprint{}) ||
		!validUUID7(record.TenantID) || !validUUID7(record.InstallationID) ||
		record.State != CertificateActive || !record.RevokedAt.IsZero() || !record.RetireAt.IsZero() ||
		record.CreatedAt.IsZero() || record.NotBefore.IsZero() || !record.NotAfter.After(record.NotBefore) ||
		record.NotAfter.Sub(record.NotBefore) > MaxCertificateLifetime || serialErr != nil ||
		len(serial) != 20 || serial[0]&0x40 == 0 {
		return false
	}
	if !record.CreatedAt.Equal(record.NotBefore) {
		return false
	}
	expectedURI, err := installationURI(record.InstallationID)
	return err == nil && record.AuthorityURI == expectedURI.String()
}

func sameCertificateInstallation(record CertificateRecord, tenantID, installationID string) bool {
	return sameIdentifier(record.TenantID, tenantID) && sameIdentifier(record.InstallationID, installationID)
}

func sameIdentifier(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func key(tenantID, installationID string) installationKey {
	return installationKey{tenantID: tenantID, installationID: installationID}
}

func contextFailed(ctx context.Context) bool {
	if ctx == nil {
		return true
	}
	return ctx.Err() != nil
}
