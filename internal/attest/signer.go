package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/flashtruth/flashtruth/internal/model"
)

// AttestationBlock holds the cryptographic digest and Ed25519 signature of an AuditReport.
type AttestationBlock struct {
	Algorithm      string `json:"algorithm"`        // "Ed25519-SHA256"
	CanonicalHash  string `json:"canonical_hash"`   // Hex SHA-256 of canonical hardware evidence
	PublicKeyHex   string `json:"public_key_hex"`   // Ed25519 Public Key
	SignatureHex   string `json:"signature_hex"`    // Ed25519 64-byte Signature
	Verified       bool   `json:"verified"`
}

// ComputeCanonicalDigest builds a deterministic SHA-256 hash over the immutable hardware telemetry of an AuditReport.
func ComputeCanonicalDigest(r *model.AuditReport) [32]byte {
	payload := fmt.Sprintf(
		"FT_V2|ID=%s|OS=%s/%s|DEV=%s|REP_BYTES=%d|VID=%s|PID=%s|SER=%s|SCSI_HEX=%s|SCSI_CAP=%s|TRUE_BYTES=%d|LAST_4K=%d|FIRST_BAD_4K=%d|MODE=%s|SCORE=%d",
		r.ReportID,
		r.HostOS, r.HostArch,
		r.Drive.DevicePath,
		r.Drive.ReportedSizeBytes,
		r.USB.VendorID, r.USB.ProductID, r.USB.SerialNumber,
		r.SCSI.InquiryHex, r.SCSI.ReadCapacityHex,
		r.CapacityProbe.TrueCapacityBytes,
		r.CapacityProbe.LastValid4KPage,
		r.CapacityProbe.FirstInvalid4KPage,
		r.CapacityProbe.FailureMode,
		r.Trust.Score,
	)
	return sha256.Sum256([]byte(payload))
}

// SignAuditReport generates a deterministic or key-seeded Ed25519 signature over the report's canonical hardware digest.
func SignAuditReport(r *model.AuditReport, seedMaterial []byte) AttestationBlock {
	digest := ComputeCanonicalDigest(r)
	seedHash := sha256.Sum256(append([]byte("FLASHTRUTH_ATTEST_KEY_V1:"), seedMaterial...))
	privKey := ed25519.NewKeyFromSeed(seedHash[:])
	pubKey := privKey.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(privKey, digest[:])

	return AttestationBlock{
		Algorithm:     "Ed25519-SHA256",
		CanonicalHash: hex.EncodeToString(digest[:]),
		PublicKeyHex:  hex.EncodeToString(pubKey),
		SignatureHex:  hex.EncodeToString(sig),
		Verified:      true,
	}
}

// VerifyAuditSignature cryptographically verifies an AuditReport against its AttestationBlock.
func VerifyAuditSignature(r *model.AuditReport, block AttestationBlock) bool {
	digest := ComputeCanonicalDigest(r)
	if hex.EncodeToString(digest[:]) != block.CanonicalHash {
		return false
	}
	pubBytes, err1 := hex.DecodeString(block.PublicKeyHex)
	sigBytes, err2 := hex.DecodeString(block.SignatureHex)
	if err1 != nil || err2 != nil || len(pubBytes) != ed25519.PublicKeySize || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubBytes), digest[:], sigBytes)
}
