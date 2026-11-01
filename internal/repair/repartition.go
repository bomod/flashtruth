package repair

import (
	"fmt"
	"math"

	"github.com/flashtruth/flashtruth/internal/model"
)

// BuildSafeRepairPlan computes the exact safe partition size (with a 3% safety margin below the physical NAND boundary)
// to quarantine fake LBA sectors on Windows, Linux, and macOS.
func BuildSafeRepairPlan(drv model.DriveInfo, capRes model.CapacityVerifyResult) model.SafeRepairPlan {
	if !capRes.Tested || !capRes.IsFakeCapacity || capRes.TrueCapacityBytes == 0 {
		return model.SafeRepairPlan{Needed: false}
	}

	// Reserve 3% safety margin below the last valid physical byte, aligned down to 16 MiB
	safeBytes := uint64(float64(capRes.TrueCapacityBytes) * 0.97)
	align16M := uint64(16 * 1024 * 1024)
	safeBytes = (safeBytes / align16M) * align16M
	if safeBytes < 64*1024*1024 {
		safeBytes = (capRes.TrueCapacityBytes / (1024 * 1024)) * (1024 * 1024)
	}

	safeMB := safeBytes / (1024 * 1024)
	safeGiB := math.Round((float64(safeBytes)/(1024.0*1024.0*1024.0))*100) / 100
	quarantinedGiB := math.Round((drv.ReportedSizeGiB-safeGiB)*100) / 100

	diskNum := drv.DiskNumber
	if diskNum < 0 {
		diskNum = 1
	}

	diskpartScript := fmt.Sprintf(
		"select disk %d\nclean\ncreate partition primary size=%d\nformat fs=exfat label=\"SAFE_%dGB\" quick\nassign letter=%s\n",
		diskNum, safeMB, int(math.Round(safeGiB)), drv.DevicePath[:1],
	)

	psCmd := fmt.Sprintf(
		"Clear-Disk -Number %d -RemoveData -Confirm:$false; New-Partition -DiskNumber %d -Size (%dMB) -DriveLetter %s | Format-Volume -FileSystem exFAT -NewFileSystemLabel 'SAFE_%dGB' -Confirm:$false",
		diskNum, diskNum, safeMB, drv.DevicePath[:1], int(math.Round(safeGiB)),
	)

	linuxCmd := fmt.Sprintf(
		"sudo parted -s %s mklabel msdos mkpart primary 1MiB %dMiB && sudo mkfs.exfat -n SAFE_%dGB %s1",
		drv.PhysicalDiskPath, safeMB, int(math.Round(safeGiB)), drv.PhysicalDiskPath,
	)

	macCmd := fmt.Sprintf(
		"diskutil partitionDisk %s MBR ExFAT SAFE_%dGB %dM FreeSpace R",
		drv.PhysicalDiskPath, int(math.Round(safeGiB)), safeMB,
	)

	return model.SafeRepairPlan{
		Needed:                true,
		TrueMaxBytes:          capRes.TrueCapacityBytes,
		RecommendedSafeBytes:  safeBytes,
		RecommendedSafeGiB:    safeGiB,
		RecommendedSafeMB:     safeMB,
		QuarantinedFakeGiB:    quarantinedGiB,
		WindowsDiskpartScript: diskpartScript,
		WindowsPowerShellCmd:  psCmd,
		LinuxPartedCmd:        linuxCmd,
		MacOSDiskutilCmd:      macCmd,
	}
}
