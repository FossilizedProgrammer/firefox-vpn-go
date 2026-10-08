package fxa

import (
	"encoding/hex"
	"testing"
)

// Vectors cross-checked against the reference implementation (PyFxA
// fxa/crypto.py) computed independently in Python:
//
//	salt1 = "identity.mozilla.com/picl/v1/quickStretch:" + email
//	qs    = PBKDF2-SHA256(password, salt1, 1000, 32)
//	authPW= HKDF-SHA256(qs, salt="", info="identity.mozilla.com/picl/v1/authPW", 32)
const (
	vecEmail        = "user@example.com"
	vecPassword     = "hunter2!"
	vecSessionToken = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
	vecQS1          = "b78262761cb1be86ac4bb959b9cc41b116520702eb9ebf513a53f83307a85dbe"
	vecAuthPW1      = "05c4ef7d1bee405c37d028a7437f00fbfed67b9e3f8f97e662c41dbe6e572157"
	vecQS2          = "750f7fee1158fe3767d20ef2ec84894517949d55e2e7881baca8bdfc7f1fc2b8"
	vecAuthPW2      = "44e812fd3ded1746fd2d4ef773899309b54ba80c5a6e3bec54d59bfa46168e52"
	vecClientSalt   = "0123456789abcdef0123456789abcdef"
	vecBearerHeader = "Bearer fxs_8915d961f8048f296c192a1568be9e15e8308243164bf4db2834d478fb24517b"
)

func TestQuickStretchV1(t *testing.T) {
	got := hex.EncodeToString(QuickStretchV1(vecEmail, vecPassword))
	if got != vecQS1 {
		t.Fatalf("QuickStretchV1 = %s, want %s", got, vecQS1)
	}
}

func TestAuthPWV1(t *testing.T) {
	qs, _ := hex.DecodeString(vecQS1)
	got := AuthPW(qs)
	if got != vecAuthPW1 {
		t.Fatalf("AuthPW(v1) = %s, want %s", got, vecAuthPW1)
	}
}

func TestQuickStretchV2(t *testing.T) {
	got := hex.EncodeToString(QuickStretchV2(vecClientSalt, vecPassword))
	if got != vecQS2 {
		t.Fatalf("QuickStretchV2 = %s, want %s", got, vecQS2)
	}
}

func TestAuthPWV2(t *testing.T) {
	qs, _ := hex.DecodeString(vecQS2)
	got := AuthPW(qs)
	if got != vecAuthPW2 {
		t.Fatalf("AuthPW(v2) = %s, want %s", got, vecAuthPW2)
	}
}

func TestSessionAuthHeader(t *testing.T) {
	got, err := SessionAuthHeader(vecSessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if got != vecBearerHeader {
		t.Fatalf("SessionAuthHeader = %s, want %s", got, vecBearerHeader)
	}
}

// HKDF-SHA256 test vector from RFC 5869 (Test Case 1).
func TestHKDFRFC5869(t *testing.T) {
	ikm := make([]byte, 22)
	for i := range ikm {
		ikm[i] = 0x0b
	}
	salt := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	info := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9}
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

	// hkdfSHA256 uses an empty-salt special case, so exercise the general
	// path via deriveKey-like call: temporarily reimplement with explicit salt.
	got := hex.EncodeToString(hkdfSHA256(ikm, salt, info, 42))
	if got != want {
		t.Fatalf("HKDF = %s, want %s", got, want)
	}
}

// PBKDF2-SHA256 test vector from RFC 7914 §11.
func TestPBKDF2RFC7914(t *testing.T) {
	got := hex.EncodeToString(pbkdf2SHA256([]byte("password"), []byte("salt"), 4096, 32))
	want := "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
	if got != want {
		t.Fatalf("PBKDF2 = %s, want %s", got, want)
	}
}
