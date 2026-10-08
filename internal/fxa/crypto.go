// Package fxa implements the parts of the Firefox Accounts protocol needed to
// obtain an OAuth token scoped for the VPN/Guardian service.
package fxa

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const fxaNamespace = "identity.mozilla.com/picl/v1/"

// hkdfSHA256 implements RFC 5869 HKDF with SHA-256.
func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	extractor := hmac.New(sha256.New, salt)
	extractor.Write(ikm)
	prk := extractor.Sum(nil)

	var out, t []byte
	for counter := byte(1); len(out) < length; counter++ {
		expander := hmac.New(sha256.New, prk)
		expander.Write(t)
		expander.Write(info)
		expander.Write([]byte{counter})
		t = expander.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// pbkdf2SHA256 implements PBKDF2 (RFC 8018) with HMAC-SHA256.
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	hashLen := sha256.Size
	blocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, blocks*hashLen)
	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		binary.Write(mac, binary.BigEndian, uint32(block))
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iterations; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// deriveKey is FxA's namespaced HKDF: empty salt, info = namespace URI.
func deriveKey(secret []byte, namespace string, size int) []byte {
	return hkdfSHA256(secret, nil, []byte(fxaNamespace+namespace), size)
}

// QuickStretchV1 derives the v1 quick-stretched password (per-account-email salt).
func QuickStretchV1(email, password string) []byte {
	salt := fxaNamespace + "quickStretch:" + email
	return pbkdf2SHA256([]byte(password), []byte(salt), 1000, 32)
}

// QuickStretchV2 derives the v2 stretched password from the server-provided
// clientSalt (a 32-hex-char token). The salt string embeds the full
// namespace prefix, matching FxA's "create_salt" format.
func QuickStretchV2(clientSalt, password string) []byte {
	salt := fxaNamespace + "quickStretchV2:" + clientSalt
	return pbkdf2SHA256([]byte(password), []byte(salt), 650000, 32)
}

// AuthPW derives the hex authPW sent to /account/login.
func AuthPW(stretched []byte) string {
	return hex.EncodeToString(deriveKey(stretched, "authPW", 32))
}

// SessionAuthHeader derives the prefixed Bearer header for auth-server
// requests from a hex sessionToken (FxA ADR-0022: "Bearer fxs_<id>", where
// id is the first 32 bytes of HKDF(sessionToken, info=.../sessionToken, 96)).
func SessionAuthHeader(sessionTokenHex string) (string, error) {
	raw, err := hex.DecodeString(sessionTokenHex)
	if err != nil {
		return "", errors.New("fxa: sessionToken must be 64 hex chars")
	}
	if len(raw) != 32 {
		return "", errors.New("fxa: sessionToken must be 32 bytes")
	}
	km := deriveKey(raw, "sessionToken", 96)
	return "Bearer fxs_" + hex.EncodeToString(km[:32]), nil
}
