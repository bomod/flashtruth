package hal

import (
	"fmt"
	"strings"

	"github.com/flashtruth/flashtruth/internal/model"
)

// RawDeviceHandle provides cross-platform unbuffered, page-aligned direct block access.
type RawDeviceHandle interface {
	LockVolume() error
	UnlockVolume() error
	ReadAtAligned(offset int64, buf []byte) error
	WriteAtAligned(offset int64, buf []byte) error
	Close() error
}

// CheckSyntheticMPtoolCapacity checks if a sector count matches known MPtool fake-capacity formulas.
func CheckSyntheticMPtoolCapacity(totalSectors uint64, sectorSize uint32) (bool, string) {
	if totalSectors == 0 || sectorSize == 0 {
		return false, ""
	}
	// Formula 1: Exact multiple of 1,000,000 MiB (e.g. 4,096,000,000 sectors = 2,000,000 MiB)
	sectorsPerMiB := uint64((1024 * 1024) / int(sectorSize))
	if sectorsPerMiB > 0 && totalSectors%sectorsPerMiB == 0 {
		totalMiB := totalSectors / sectorsPerMiB
		if totalMiB >= 100000 && totalMiB%100000 == 0 {
			return true, fmt.Sprintf("Total sectors (%d = 0x%X) is an exact synthetic multiple of %d MiB (%d * 100,000 MiB), a classic FirstChip/Chipsbank MPtool manual capacity entry.", totalSectors, totalSectors, totalMiB, totalMiB/100000)
		}
		if totalMiB >= 64000 && totalMiB%1000 == 0 {
			return true, fmt.Sprintf("Total sectors (%d = 0x%X) equals an exact round %d,000 MiB, typical of factory MPtool capacity spoofing.", totalSectors, totalSectors, totalMiB/1000)
		}
	}
	// Formula 2: Exact decimal billion bytes / 512 (e.g., 2,000,000,000,000 / 512 = 3,906,250,000)
	totalBytes := totalSectors * uint64(sectorSize)
	if totalBytes >= 500_000_000_000 && totalBytes%100_000_000_000 == 0 {
		return true, fmt.Sprintf("Total byte size (%d) is an exact synthetic multiple of 100,000,000,000 bytes.", totalBytes)
	}
	return false, ""
}

// AnalyzeUSB3Mismatch checks if the device name claims USB 3.x while running on USB 2.0.
func AnalyzeUSB3Mismatch(usb *model.USBTopology, scsi *model.SCSIFingerprint) {
	combinedName := strings.ToLower(usb.ProductString + " " + scsi.ProductID16 + " " + usb.PNPDeviceID)
	if strings.Contains(combinedName, "3.0") || strings.Contains(combinedName, "3.1") || strings.Contains(combinedName, "3.2") || strings.Contains(combinedName, "superspeed") {
		usb.ClaimedUSB3InName = true
	}
	isUSB2Rev := strings.HasPrefix(usb.Revision, "02") || usb.Revision == "2.00" || usb.Revision == "0200"
	isHSBIOSPort := strings.Contains(strings.ToUpper(usb.BIOSDevicePath), ".HS")
	isUSB2Speed := strings.Contains(strings.ToLower(usb.NegotiatedSpeed), "usb 2.0") || strings.Contains(strings.ToLower(usb.NegotiatedSpeed), "480")

	if isHSBIOSPort || isUSB2Rev || isUSB2Speed {
		if usb.NegotiatedSpeed == "" {
			usb.NegotiatedSpeed = "High-Speed (USB 2.0 - 480 Mbps Max)"
		}
		if usb.ClaimedUSB3InName {
			usb.IsFakeUSB3Speed = true
		}
	} else if strings.Contains(strings.ToUpper(usb.BIOSDevicePath), ".SS") {
		if usb.NegotiatedSpeed == "" {
			usb.NegotiatedSpeed = "SuperSpeed (USB 3.x - 5000+ Mbps)"
		}
	}
}
