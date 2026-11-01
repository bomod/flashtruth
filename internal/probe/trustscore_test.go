package probe

import (
	"testing"

	"github.com/flashtruth/flashtruth/internal/model"
)

func TestEvaluateTrustScore_CounterfeitVsClampedVsAuthentic(t *testing.T) {
	// Case 1: Raw un-clamped counterfeit 2TB USB drive (048D:1234)
	counterfeitReport := &model.AuditReport{
		Drive: model.DriveInfo{
			ReportedSizeGiB:   1953.13,
			ReportedSizeGB:    2097.15,
			TotalSectors:      4096000000,
			PartitionStartLBA: 32,
		},
		USB: model.USBTopology{
			VendorID:        "048D",
			ProductID:       "1234",
			IsFakeUSB3Speed: true,
		},
		SCSI: model.SCSIFingerprint{
			ReportedTotalSectors:   4096000000,
			IsSyntheticMPtoolRound: true,
		},
		ControllerMatch: model.ControllerSignature{
			Category: "KNOWN_FAKE_TEMPLATE",
		},
		CapacityProbe: model.CapacityVerifyResult{
			Tested:            true,
			IsFakeCapacity:    true,
			TrueCapacityGiB:   29.50,
			TrueCapacityGB:    31.68,
			TrueCapacityBytes: 31675400192,
			FakePercentage:    98.49,
		},
		SpeedMetrics: model.SpeedBenchmark{
			Tested:         true,
			WriteSpeedMBps: 0.30,
			ReadSpeedMBps:  30.57,
		},
	}

	sc1 := EvaluateTrustScore(counterfeitReport)
	if sc1.Score != 0 || sc1.Grade != "F // COUNTERFEIT" || sc1.IsAuthentic {
		t.Fatalf("expected 0 / F // COUNTERFEIT for raw fake drive, got score=%d grade=%s auth=%v", sc1.Score, sc1.Grade, sc1.IsAuthentic)
	}

	// Case 2: Repaired & Clamped USB drive (Partition clamped to 28.59 GiB inside verified 29.81 GiB physical NAND)
	clampedReport := *counterfeitReport
	clampedReport.Drive.ReportedSizeGiB = 28.59
	clampedReport.Drive.ReportedSizeGB = 30.70
	clampedReport.Drive.TotalSectors = 59965440
	clampedReport.Drive.PartitionStartLBA = 2048
	clampedReport.CapacityProbe.IsFakeCapacity = false
	clampedReport.CapacityProbe.FakePercentage = 0

	sc2 := EvaluateTrustScore(&clampedReport)
	if sc2.Score != 85 || sc2.Grade != "A // REPAIRED & SAFE" || !sc2.IsAuthentic {
		t.Fatalf("expected 85 / A // REPAIRED & SAFE for clamped safe drive, got score=%d grade=%s auth=%v", sc2.Score, sc2.Grade, sc2.IsAuthentic)
	}

	// Case 3: Genuine Tier-1 Drive
	genuineReport := &model.AuditReport{
		Drive: model.DriveInfo{
			ReportedSizeGiB:   953.87,
			ReportedSizeGB:    1024.21,
			TotalSectors:      2000409264,
			PartitionStartLBA: 2048,
		},
		ControllerMatch: model.ControllerSignature{
			Category: "AUTHENTIC_BRAND",
		},
		CapacityProbe: model.CapacityVerifyResult{
			Tested:         true,
			IsFakeCapacity: false,
		},
		SpeedMetrics: model.SpeedBenchmark{
			Tested:         true,
			WriteSpeedMBps: 1850.0,
			ReadSpeedMBps:  3200.0,
		},
		SecurityScan: model.MalwareScanResult{
			Scanned: true,
			IsClean: true,
		},
	}

	sc3 := EvaluateTrustScore(genuineReport)
	if sc3.Score != 100 || sc3.Grade != "A+ // AUTHENTIC" || !sc3.IsAuthentic {
		t.Fatalf("expected 100 / A+ // AUTHENTIC for genuine drive, got score=%d grade=%s auth=%v", sc3.Score, sc3.Grade, sc3.IsAuthentic)
	}
}
