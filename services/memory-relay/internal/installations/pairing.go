package installations

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"time"
)

const (
	// PairingSecretBytes is the exact entropy required for a pairing token.
	PairingSecretBytes = 32
	// MaxPairingLifetime is the longest permitted pairing-code lifetime.
	MaxPairingLifetime = 10 * time.Minute
	pairingTokenLength = 43
)

var pairingTokenDomain = []byte("scalevault-relay-pairing-v1\x00")

// PairingVerifier is the non-secret, indexed value stored by the relay.
type PairingVerifier [sha256.Size]byte

// PairingState is the closed lifecycle of a pairing record.
type PairingState string

const (
	PairingPending  PairingState = "pending"
	PairingConsumed PairingState = "consumed"
)

// PairingRecord is the secret-free state persisted by a pairing storage layer.
type PairingRecord struct {
	Verifier       PairingVerifier
	TenantID       string
	InstallationID string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	State          PairingState
	ConsumedAt     time.Time
}

// IssuedPairing contains the one-time token and its storage-safe record. The
// token is intentionally private so formatting the value does not reveal it.
type IssuedPairing struct {
	token  string
	record PairingRecord
}

// String prevents logging or formatting from revealing the one-time token.
func (IssuedPairing) String() string { return "IssuedPairing(<redacted>)" }

// GoString prevents direct-contextualized logging from revealing the token.
func (IssuedPairing) GoString() string { return "IssuedPairing(<redacted>)" }

// Token returns the one-time pairing token only when the caller deliberately
// asks to reveal it.
func (issued IssuedPairing) Token() string { return issued.token }

// Record returns the secret-free pairing record used by Store.CreatePairing.
func (issued IssuedPairing) Record() PairingRecord { return issued.record }

// PairingIssuer creates exact-version pairing material with injected entropy
// and time sources.
type PairingIssuer struct {
	pepper []byte
	random io.Reader
	clock  func() time.Time
}

// NewPairingIssuer constructs a pairing issuer. The pepper must be at least
// 256 bits and must never be stored beside pairing records.
func NewPairingIssuer(pepper []byte, random io.Reader, clock func() time.Time) (*PairingIssuer, error) {
	if len(pepper) < 32 || random == nil || clock == nil {
		return nil, ErrEnrollmentFailed
	}
	return &PairingIssuer{
		pepper: append([]byte(nil), pepper...),
		random: random,
		clock:  clock,
	}, nil
}

// Issue generates one pairing token and its HMAC-verifier record.
func (issuer *PairingIssuer) Issue(tenantID, installationID string, lifetime time.Duration) (IssuedPairing, error) {
	if issuer == nil || !validUUID7(tenantID) || !validUUID7(installationID) ||
		lifetime <= 0 || lifetime > MaxPairingLifetime {
		return IssuedPairing{}, ErrEnrollmentFailed
	}
	secret := make([]byte, PairingSecretBytes)
	if _, err := io.ReadFull(issuer.random, secret); err != nil {
		return IssuedPairing{}, ErrEnrollmentFailed
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	if len(token) != pairingTokenLength {
		return IssuedPairing{}, ErrEnrollmentFailed
	}
	createdAt := issuer.clock().UTC()
	if createdAt.IsZero() {
		return IssuedPairing{}, ErrEnrollmentFailed
	}
	record := PairingRecord{
		Verifier:       pairingVerifier(secret, issuer.pepper),
		TenantID:       tenantID,
		InstallationID: installationID,
		CreatedAt:      createdAt,
		ExpiresAt:      createdAt.Add(lifetime),
		State:          PairingPending,
	}
	return IssuedPairing{token: token, record: record}, nil
}

// VerifyToken converts an exact pairing token into its storage lookup value.
// All malformed token shapes are deliberately indistinguishable.
func (issuer *PairingIssuer) VerifyToken(token string) (PairingVerifier, error) {
	if issuer == nil {
		return PairingVerifier{}, ErrEnrollmentFailed
	}
	secret, err := parsePairingToken(token)
	if err != nil {
		return PairingVerifier{}, ErrEnrollmentFailed
	}
	return pairingVerifier(secret[:], issuer.pepper), nil
}

func parsePairingToken(token string) ([PairingSecretBytes]byte, error) {
	var secret [PairingSecretBytes]byte
	if len(token) != pairingTokenLength {
		return secret, ErrEnrollmentFailed
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != PairingSecretBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != token {
		return secret, ErrEnrollmentFailed
	}
	copy(secret[:], decoded)
	return secret, nil
}

func pairingVerifier(secret, pepper []byte) PairingVerifier {
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write(pairingTokenDomain)
	_, _ = mac.Write(secret)
	var verifier PairingVerifier
	copy(verifier[:], mac.Sum(nil))
	return verifier
}
