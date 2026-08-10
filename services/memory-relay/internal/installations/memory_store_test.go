package installations

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/x509/pkix"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryStoreRedeemsPairingExactlyOnceAtomically(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	pairing, certificate := pairingAndCertificate(t, testNow, time.Minute, testTenantID, testInstallationID, 0x41)
	if err := store.CreatePairing(ctx, pairing.Record()); err != nil {
		t.Fatalf("store pairing: %v", err)
	}
	redemption := PairingRedemption{
		Verifier:       pairing.Record().Verifier,
		TenantID:       testTenantID,
		InstallationID: testInstallationID,
		RedeemedAt:     testNow.Add(time.Second),
		Certificate:    certificate,
	}

	var successes atomic.Int32
	var group sync.WaitGroup
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			if store.RedeemPairing(ctx, redemption) == nil {
				successes.Add(1)
			}
		}()
	}
	group.Wait()
	if successes.Load() != 1 {
		t.Fatalf("expected exactly one redemption, got %d", successes.Load())
	}
	if _, err := store.FindPairing(ctx, redemption.Verifier, testNow.Add(time.Second)); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("consumed pairing remained findable: %v", err)
	}
	active, err := store.CertificateActive(
		ctx, testTenantID, testInstallationID, certificate.Fingerprint, testNow.Add(time.Second),
	)
	if err != nil || !active {
		t.Fatalf("redeemed certificate was not active: %t, %v", active, err)
	}
}

func TestMemoryStoreRejectsExpiryAndIdentityMismatchWithoutConsumption(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	pairing, certificate := pairingAndCertificate(t, testNow, time.Minute, testTenantID, testInstallationID, 0x42)
	if err := store.CreatePairing(ctx, pairing.Record()); err != nil {
		t.Fatalf("store pairing: %v", err)
	}

	requests := []PairingRedemption{
		{
			Verifier: pairing.Record().Verifier, TenantID: otherTenantID,
			InstallationID: testInstallationID, RedeemedAt: testNow.Add(time.Second), Certificate: certificate,
		},
		{
			Verifier: pairing.Record().Verifier, TenantID: testTenantID,
			InstallationID: otherInstallationID, RedeemedAt: testNow.Add(time.Second), Certificate: certificate,
		},
	}
	for index, request := range requests {
		if err := store.RedeemPairing(ctx, request); !errors.Is(err, ErrEnrollmentFailed) ||
			err.Error() != "enrollment failed" {
			t.Errorf("mismatch %d returned non-safe error %v", index, err)
		}
	}
	if _, err := store.FindPairing(ctx, pairing.Record().Verifier, testNow.Add(time.Second)); err != nil {
		t.Fatalf("mismatch consumed pairing: %v", err)
	}

	expired := PairingRedemption{
		Verifier: pairing.Record().Verifier, TenantID: testTenantID,
		InstallationID: testInstallationID, RedeemedAt: pairing.Record().ExpiresAt, Certificate: certificate,
	}
	if err := store.RedeemPairing(ctx, expired); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected expiry failure, got %v", err)
	}
	if _, err := store.FindPairing(ctx, pairing.Record().Verifier, testNow.Add(time.Second)); err != nil {
		t.Fatalf("expiry consumed pairing: %v", err)
	}
	if _, err := store.FindPairing(ctx, pairing.Record().Verifier, pairing.Record().ExpiresAt); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expired pairing remained redeemable: %v", err)
	}
}

func TestMemoryStoreRotationOverlapAndRevocation(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	pairing, current := pairingAndCertificate(t, testNow, time.Minute, testTenantID, testInstallationID, 0x51)
	if err := store.CreatePairing(ctx, pairing.Record()); err != nil {
		t.Fatalf("store pairing: %v", err)
	}
	if err := store.RedeemPairing(ctx, PairingRedemption{
		Verifier: pairing.Record().Verifier, TenantID: testTenantID, InstallationID: testInstallationID,
		RedeemedAt: testNow.Add(time.Second), Certificate: current,
	}); err != nil {
		t.Fatalf("redeem current certificate: %v", err)
	}

	rotationAt := testNow.Add(23 * 24 * time.Hour)
	_, replacement := pairingAndCertificate(
		t, testNow.Add(22*24*time.Hour), time.Minute, testTenantID, testInstallationID, 0x52,
	)
	if err := store.RotateCertificate(ctx, CertificateRotation{
		TenantID: testTenantID, InstallationID: testInstallationID,
		CurrentFingerprint: current.Fingerprint, Replacement: replacement,
		RotatedAt: testNow.Add(22 * 24 * time.Hour), Overlap: time.Hour,
	}); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("early rotation returned %v", err)
	}
	if err := store.RotateCertificate(ctx, CertificateRotation{
		TenantID: testTenantID, InstallationID: testInstallationID,
		CurrentFingerprint: current.Fingerprint, Replacement: replacement,
		RotatedAt: rotationAt, Overlap: RotationMaxOverlap,
	}); err != nil {
		t.Fatalf("rotate certificate: %v", err)
	}
	for _, fingerprint := range []CertificateFingerprint{current.Fingerprint, replacement.Fingerprint} {
		active, err := store.CertificateActive(ctx, testTenantID, testInstallationID, fingerprint, rotationAt)
		if err != nil || !active {
			t.Fatalf("overlap certificate was not active: %t, %v", active, err)
		}
	}
	oldActive, err := store.CertificateActive(
		ctx, testTenantID, testInstallationID, current.Fingerprint, rotationAt.Add(RotationMaxOverlap),
	)
	if err != nil || oldActive {
		t.Fatalf("retiring certificate survived overlap: %t, %v", oldActive, err)
	}
	newActive, err := store.CertificateActive(
		ctx, testTenantID, testInstallationID, replacement.Fingerprint, replacement.NotAfter,
	)
	if err != nil || newActive {
		t.Fatalf("expired certificate remained active: %t, %v", newActive, err)
	}

	if err := store.RevokeCertificate(
		ctx, testTenantID, testInstallationID, replacement.Fingerprint, rotationAt.Add(time.Hour),
	); err != nil {
		t.Fatalf("revoke replacement: %v", err)
	}
	if err := store.RevokeCertificate(
		ctx, testTenantID, testInstallationID, replacement.Fingerprint, rotationAt.Add(2*time.Hour),
	); err != nil {
		t.Fatalf("idempotent replacement revocation: %v", err)
	}
	active, err := store.CertificateActive(
		ctx, testTenantID, testInstallationID, replacement.Fingerprint, rotationAt.Add(2*time.Hour),
	)
	if err != nil || active {
		t.Fatalf("revoked certificate remained active: %t, %v", active, err)
	}
}

func TestMemoryStoreInstallationRevocationIsPermanent(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	pairing, certificate := pairingAndCertificate(t, testNow, time.Minute, testTenantID, testInstallationID, 0x61)
	if err := store.CreatePairing(ctx, pairing.Record()); err != nil {
		t.Fatalf("store pairing: %v", err)
	}
	if err := store.RedeemPairing(ctx, PairingRedemption{
		Verifier: pairing.Record().Verifier, TenantID: testTenantID, InstallationID: testInstallationID,
		RedeemedAt: testNow.Add(time.Second), Certificate: certificate,
	}); err != nil {
		t.Fatalf("redeem certificate: %v", err)
	}
	revokedAt := testNow.Add(2 * time.Second)
	if err := store.RevokeInstallation(ctx, testTenantID, testInstallationID, revokedAt); err != nil {
		t.Fatalf("revoke installation: %v", err)
	}
	if err := store.RevokeInstallation(ctx, testTenantID, testInstallationID, revokedAt.Add(time.Second)); err != nil {
		t.Fatalf("idempotent installation revocation: %v", err)
	}
	active, err := store.CertificateActive(
		ctx, testTenantID, testInstallationID, certificate.Fingerprint, revokedAt,
	)
	if err != nil || active {
		t.Fatalf("installation certificate remained active: %t, %v", active, err)
	}
	newPairingIssuer := mustPairingIssuer(t, bytes.Repeat([]byte{0x62}, 32), revokedAt)
	newPairing, err := newPairingIssuer.Issue(testTenantID, testInstallationID, time.Minute)
	if err != nil {
		t.Fatalf("issue new pairing: %v", err)
	}
	if err := store.CreatePairing(ctx, newPairing.Record()); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("revoked installation accepted new pairing: %v", err)
	}
}

func pairingAndCertificate(
	t *testing.T,
	now time.Time,
	pairingLifetime time.Duration,
	tenantID string,
	installationID string,
	entropy byte,
) (IssuedPairing, CertificateRecord) {
	t.Helper()
	pairingIssuer := mustPairingIssuer(t, bytes.Repeat([]byte{entropy}, 32), now)
	pairing, err := pairingIssuer.Issue(tenantID, installationID, pairingLifetime)
	if err != nil {
		t.Fatalf("issue pairing: %v", err)
	}
	csrDER, _ := makeCSR(t, elliptic.P256(), pkix.Name{}, nil, nil)
	certificateIssuer := mustCertificateIssuer(t, now, bytes.Repeat([]byte{entropy}, 20), nil)
	issuedCertificate, err := certificateIssuer.Issue(
		context.Background(), tenantID, installationID, csrDER, MaxCertificateLifetime,
	)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	return pairing, issuedCertificate.Record()
}
