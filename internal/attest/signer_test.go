package attest

import (
	"testing"

	"github.com/flashtruth/flashtruth/internal/model"
)

func TestSignAndVerifyAuditReport(t *testing.T) {
	rep := &model.AuditReport{
		ReportID: "FT-TEST0001",
		HostOS:   "windows",
		HostArch: "amd64",
		Drive: model.DriveInfo{
			DevicePath:        "D:",
			ReportedSizeBytes: 2097152000000,
		},
		USB: model.USBTopology{
			VendorID:     "048D",
			ProductID:    "1234",
			SerialNumber: "9112511085014663328",
		},
		CapacityProbe: model.CapacityVerifyResult{
			TrueCapacityBytes:  32014008320,
			LastValid4KPage:    0x7742EF,
			FirstInvalid4KPage: 0x7742F0,
			FailureMode:        "BLACK_HOLE_0xFF",
		},
		Trust: model.TrustScorecard{
			Score: 0,
		},
	}

	att := SignAuditReport(rep, []byte("unit-test-seed"))
	if !VerifyAuditSignature(rep, att) {
		t.Fatalf("expected valid Ed25519 signature verification")
	}

	// Tamper with TrueCapacityBytes and verify signature fails
	rep.CapacityProbe.TrueCapacityBytes = 2097152000000
	if VerifyAuditSignature(rep, att) {
		t.Fatalf("expected tampered report to fail Ed25519 signature verification")
	}
}
