package probe

import (
	"fmt"

	"github.com/flashtruth/flashtruth/internal/model"
)

// EvaluateTrustScore computes the 0-100 authenticity score, grade, and detailed evidence items.
func EvaluateTrustScore(r *model.AuditReport) model.TrustScorecard {
	score := 100
	var ev []model.EvidenceItem

	// 1. Physical Capacity Binary Search Check
	if r.CapacityProbe.Tested {
		if r.CapacityProbe.IsFakeCapacity {
			score -= 65
			ev = append(ev, model.EvidenceItem{
				Category: "PHYSICAL_CAPACITY",
				Status:   "FAIL",
				Impact:   -65,
				TitleEN:  "Counterfeit Physical NAND Capacity Detected",
				DetailEN: fmt.Sprintf("Drive claims %.2f GiB (%.2f TB), but hardware binary search proved true physical capacity is only %.3f GiB (%.2f GB). %.2f%% of reported space is phantom void (%s).",
					r.Drive.ReportedSizeGiB, r.Drive.ReportedSizeGB/1000.0, r.CapacityProbe.TrueCapacityGiB, r.CapacityProbe.TrueCapacityGB, r.CapacityProbe.FakePercentage, r.CapacityProbe.FailureMode),
				RawProof: fmt.Sprintf("LastValid4KPage=0x%X (Sector %d = %d bytes) | FirstInvalid4KPage=0x%X -> Read=0xFFFFFFFFFFFFFFFF",
					r.CapacityProbe.LastValid4KPage, r.CapacityProbe.TrueValidSectors512-1, r.CapacityProbe.TrueCapacityBytes, r.CapacityProbe.FirstInvalid4KPage),
			})
		} else {
			ev = append(ev, model.EvidenceItem{
				Category: "PHYSICAL_CAPACITY",
				Status:   "PASS",
				Impact:   0,
				TitleEN:  "Physical NAND Capacity Verified Genuine",
				DetailEN: fmt.Sprintf("All hardware probe points across %.2f GiB passed unbuffered write/read verification.", r.Drive.ReportedSizeGiB),
				RawProof: fmt.Sprintf("VerifiedBytes=%d", r.CapacityProbe.TrueCapacityBytes),
			})
		}
	}

	// 2. Controller VID:PID & SCSI Signature Check
	switch r.ControllerMatch.Category {
	case "KNOWN_FAKE_TEMPLATE":
		score -= 25
		ev = append(ev, model.EvidenceItem{
			Category: "CONTROLLER_IDENTITY",
			Status:   "FAIL",
			Impact:   -25,
			TitleEN:  "Known Counterfeit MPtool Controller Signature",
			DetailEN: r.ControllerMatch.DescriptionEN,
			RawProof: fmt.Sprintf("VID=%s PID=%s SCSI='%s %s' Rev='%s'", r.USB.VendorID, r.USB.ProductID, r.SCSI.VendorID8, r.SCSI.ProductID16, r.SCSI.ProductRev4),
		})
	case "AUTHENTIC_BRAND":
		ev = append(ev, model.EvidenceItem{
			Category: "CONTROLLER_IDENTITY",
			Status:   "PASS",
			Impact:   0,
			TitleEN:  "Registered Authentic Tier-1 Manufacturer ID",
			DetailEN: r.ControllerMatch.DescriptionEN,
			RawProof: fmt.Sprintf("VID=%s PID=%s Owner=%s", r.USB.VendorID, r.USB.ProductID, r.ControllerMatch.RegisteredOwner),
		})
	default:
		ev = append(ev, model.EvidenceItem{
			Category: "CONTROLLER_IDENTITY",
			Status:   "WARN",
			Impact:   -5,
			TitleEN:  "Generic / White-Label USB Controller",
			DetailEN: r.ControllerMatch.DescriptionEN,
			RawProof: fmt.Sprintf("VID=%s PID=%s", r.USB.VendorID, r.USB.ProductID),
		})
		score -= 5
	}

	// 3. USB 3.x vs USB 2.0 Speed & Port Check
	if r.USB.IsFakeUSB3Speed {
		score -= 15
		ev = append(ev, model.EvidenceItem{
			Category: "USB_GENERATION",
			Status:   "FAIL",
			Impact:   -15,
			TitleEN:  "Fake USB 3.0 Marketing Claim (Hardware is USB 2.0)",
			DetailEN: fmt.Sprintf("Device advertises '%s' (USB 3.0), but enumerates on USB 2.0 High-Speed bus (%s) with hardware revision REV_%s.",
				r.USB.ProductString, r.USB.BIOSDevicePath, r.USB.Revision),
			RawProof: fmt.Sprintf("PNP=%s | BIOS=%s | Rev=%s", r.USB.PNPDeviceID, r.USB.BIOSDevicePath, r.USB.Revision),
		})
	}

	// 4. Factory MPtool MBR LBA-32 & Synthetic Sector Count Check
	if r.BootForensics.IsMPtoolLBA32Layout || r.SCSI.IsSyntheticMPtoolRound {
		score -= 15
		ev = append(ev, model.EvidenceItem{
			Category: "BOOT_FORENSICS",
			Status:   "FAIL",
			Impact:   -15,
			TitleEN:  "Factory Capacity-Spoofing MPtool Partition Fingerprint",
			DetailEN: fmt.Sprintf("Partition starts at LBA %d (instead of standard OS LBA 2048 alignment), and total sector count (%d) matches a synthetic MPtool round formula.",
				r.Drive.PartitionStartLBA, r.Drive.TotalSectors),
			RawProof: fmt.Sprintf("PartitionStartLBA=%d | ReadCapacityHex=%s | MBRPart1=%s", r.Drive.PartitionStartLBA, r.SCSI.ReadCapacityHex, r.BootForensics.MBRPartitionEntry1Hex),
		})
	}

	// 5. True Unbuffered NAND Write Speed Check
	if r.SpeedMetrics.Tested {
		if r.SpeedMetrics.WriteSpeedMBps < 3.5 {
			score -= 10
			ev = append(ev, model.EvidenceItem{
				Category: "NAND_PERFORMANCE",
				Status:   "FAIL",
				Impact:   -10,
				TitleEN:  fmt.Sprintf("Severely Degraded Hardware Write Speed (%.2f MB/s)", r.SpeedMetrics.WriteSpeedMBps),
				DetailEN: fmt.Sprintf("True DMA unbuffered write speed is only %.2f MB/s (Read: %.2f MB/s), indicating scrap/downgrade NAND flash.",
					r.SpeedMetrics.WriteSpeedMBps, r.SpeedMetrics.ReadSpeedMBps),
				RawProof: fmt.Sprintf("Write=%.2f MB/s | Read=%.2f MB/s | MaxChunkLatency=%.1f ms", r.SpeedMetrics.WriteSpeedMBps, r.SpeedMetrics.ReadSpeedMBps, r.SpeedMetrics.MaxChunkWriteMs),
			})
		} else {
			ev = append(ev, model.EvidenceItem{
				Category: "NAND_PERFORMANCE",
				Status:   "PASS",
				Impact:   0,
				TitleEN:  fmt.Sprintf("Healthy Hardware Read/Write Speed (Write: %.2f MB/s | Read: %.2f MB/s)", r.SpeedMetrics.WriteSpeedMBps, r.SpeedMetrics.ReadSpeedMBps),
				DetailEN: r.SpeedMetrics.NANDQualityEstimate,
				RawProof: fmt.Sprintf("Write=%.2f MB/s | Read=%.2f MB/s", r.SpeedMetrics.WriteSpeedMBps, r.SpeedMetrics.ReadSpeedMBps),
			})
		}
	}

	// 6. Malware & Hidden Artifacts Check
	if r.SecurityScan.Scanned {
		if !r.SecurityScan.IsClean {
			score -= 20
			ev = append(ev, model.EvidenceItem{
				Category: "SECURITY_MALWARE",
				Status:   "FAIL",
				Impact:   -20,
				TitleEN:  fmt.Sprintf("Detected %d Suspicious or Malicious Files on Drive", r.SecurityScan.SuspiciousCount),
				DetailEN: "Drive contains suspicious executables, autorun, or shortcut files.",
				RawProof: fmt.Sprintf("SuspiciousCount=%d", r.SecurityScan.SuspiciousCount),
			})
		} else {
			ev = append(ev, model.EvidenceItem{
				Category: "SECURITY_MALWARE",
				Status:   "PASS",
				Impact:   0,
				TitleEN:  "Drive is Clean of Malware, Worms, and Suspicious Hidden Files",
				DetailEN: "Zero malware, autorun.inf, .lnk worms, or prior deleted files found in raw root directory cluster.",
				RawProof: fmt.Sprintf("TotalFiles=%d | Suspicious=0 | PriorDeleted=%d", r.SecurityScan.TotalFiles, r.BootForensics.PriorDeletedFilesCount),
			})
		}
	}

	if score < 0 {
		score = 0
	}

	isClampedSafe := r.CapacityProbe.Tested && !r.CapacityProbe.IsFakeCapacity && r.SCSI.ReportedTotalSectors > r.Drive.TotalSectors*2
	if isClampedSafe && score < 85 {
		score = 85
	}

	var grade, verdictEN string
	isAuthentic := !r.CapacityProbe.IsFakeCapacity && score >= 70

	switch {
	case isClampedSafe:
		grade = "A // REPAIRED & SAFE"
		verdictEN = "REPAIRED & SAFE STORAGE MEDIA — Active partition is 100% verified physical NAND; phantom LBA space is quarantined"
	case r.CapacityProbe.IsFakeCapacity || score < 30:
		grade = "F // COUNTERFEIT"
		verdictEN = "COUNTERFEIT STORAGE MEDIA — Physical NAND capacity is a fraction of advertised LBA count (High Data Loss Risk)"
	case score < 60:
		grade = "D // HIGH RISK"
		verdictEN = "HIGH-RISK STORAGE MEDIA — Substandard or reprogrammed generic controller detected"
	case score < 80:
		grade = "B // VERIFIED GENERIC"
		verdictEN = "VERIFIED CAPACITY — Physical NAND matches reported volume size (Generic OEM Controller)"
	default:
		grade = "A+ // AUTHENTIC"
		verdictEN = "AUTHENTIC TIER-1 MEDIA — Physical NAND capacity, bus speed, and OEM controller verified"
	}

	return model.TrustScorecard{
		Score:       score,
		Grade:       grade,
		VerdictEN:   verdictEN,
		IsAuthentic: isAuthentic,
		Evidence:    ev,
	}
}
