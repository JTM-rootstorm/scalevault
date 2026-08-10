package installations

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	testTenantID        = "019c0000-0000-7000-8000-000000000001"
	testInstallationID  = "019c0000-0000-7000-8000-000000000002"
	otherTenantID       = "019c0000-0000-7000-8000-000000000003"
	otherInstallationID = "019c0000-0000-7000-8000-000000000004"
)

var testNow = time.Date(2026, 8, 10, 12, 0, 0, 123456789, time.UTC)

func TestPairingIssuerCreatesExactTokenAndVerifier(t *testing.T) {
	secret := make([]byte, PairingSecretBytes)
	for index := range secret {
		secret[index] = byte(index)
	}
	issuer := mustPairingIssuer(t, secret, testNow)

	issued, err := issuer.Issue(testTenantID, testInstallationID, MaxPairingLifetime)
	if err != nil {
		t.Fatalf("issue pairing: %v", err)
	}
	expected := base64.RawURLEncoding.EncodeToString(secret)
	if issued.Token() != expected || len(issued.Token()) != pairingTokenLength || strings.Contains(issued.Token(), "=") {
		t.Fatalf("unexpected exact token shape %q", issued.Token())
	}
	record := issued.Record()
	if record.TenantID != testTenantID || record.InstallationID != testInstallationID ||
		record.CreatedAt != testNow || record.ExpiresAt != testNow.Add(MaxPairingLifetime) ||
		record.State != PairingPending || !record.ConsumedAt.IsZero() {
		t.Fatalf("unexpected pairing record %#v", record)
	}
	verifier, err := issuer.VerifyToken(issued.Token())
	if err != nil || verifier != record.Verifier || verifier == (PairingVerifier{}) {
		t.Fatalf("unexpected verifier result %x, %v", verifier, err)
	}
	formatted := fmt.Sprintf("%v %+v %#v", issued, issued, issued)
	if strings.Contains(formatted, issued.Token()) || strings.Contains(formatted, expected[:12]) {
		t.Fatalf("formatted issuance exposed token: %q", formatted)
	}
}

func TestPairingTokenParsingIsExactAndSafe(t *testing.T) {
	issuer := mustPairingIssuer(t, bytes.Repeat([]byte{0x5a}, PairingSecretBytes), testNow)
	issued, err := issuer.Issue(testTenantID, testInstallationID, time.Minute)
	if err != nil {
		t.Fatalf("issue pairing: %v", err)
	}
	valid := issued.Token()
	malformed := []string{
		"",
		valid[:len(valid)-1],
		valid + "A",
		valid + "=",
		valid[:10] + "+" + valid[11:],
		valid[:10] + "/" + valid[11:],
		valid[:10] + "\n" + valid[10:],
	}
	for _, token := range malformed {
		_, err := issuer.VerifyToken(token)
		if !errors.Is(err, ErrEnrollmentFailed) || err.Error() != "enrollment failed" {
			t.Errorf("token %q returned non-safe error %v", token, err)
		}
	}

	other, err := NewPairingIssuer(bytes.Repeat([]byte{0x22}, 32), bytes.NewReader(nil), func() time.Time { return testNow })
	if err != nil {
		t.Fatalf("construct other issuer: %v", err)
	}
	firstVerifier, _ := issuer.VerifyToken(valid)
	alternateToken := "A" + valid[1:]
	if alternateToken == valid {
		alternateToken = "B" + valid[1:]
	}
	alternateVerifier, err := issuer.VerifyToken(alternateToken)
	if err != nil || alternateVerifier == firstVerifier {
		t.Fatalf("alternate exact token did not produce an independent verifier: %v", err)
	}
	secondVerifier, _ := other.VerifyToken(valid)
	if firstVerifier == secondVerifier {
		t.Fatal("different peppers produced the same verifier")
	}
}

func TestPairingIssuerRejectsInvalidConfigurationAndLifetime(t *testing.T) {
	if _, err := NewPairingIssuer(make([]byte, 31), bytes.NewReader(nil), func() time.Time { return testNow }); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected short-pepper failure, got %v", err)
	}
	issuer := mustPairingIssuer(t, bytes.Repeat([]byte{1}, PairingSecretBytes), testNow)
	for _, lifetime := range []time.Duration{0, -time.Second, MaxPairingLifetime + time.Nanosecond} {
		if _, err := issuer.Issue(testTenantID, testInstallationID, lifetime); !errors.Is(err, ErrEnrollmentFailed) {
			t.Errorf("expected lifetime %s to fail, got %v", lifetime, err)
		}
	}
	if _, err := issuer.Issue(strings.ToUpper(testTenantID), testInstallationID, time.Minute); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected noncanonical UUID failure, got %v", err)
	}
	shortEntropy := mustPairingIssuer(t, make([]byte, PairingSecretBytes-1), testNow)
	if _, err := shortEntropy.Issue(testTenantID, testInstallationID, time.Minute); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected short entropy failure, got %v", err)
	}
}

func mustPairingIssuer(t *testing.T, entropy []byte, now time.Time) *PairingIssuer {
	t.Helper()
	issuer, err := NewPairingIssuer(
		bytes.Repeat([]byte{0xa5}, 32),
		bytes.NewReader(entropy),
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatalf("construct pairing issuer: %v", err)
	}
	return issuer
}
