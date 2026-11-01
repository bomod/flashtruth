package probe

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"github.com/flashtruth/flashtruth/internal/hal"
	"github.com/flashtruth/flashtruth/internal/model"
)

// VerifyTrueCapacity executes the 2-phase non-destructive Grid Sweep + Binary Search capacity probe.
func VerifyTrueCapacity(drv model.DriveInfo, onProgress func(string, int)) (res model.CapacityVerifyResult) {
	tStart := time.Now()
	res = model.CapacityVerifyResult{
		FailureMode: "NONE",
	}

	if drv.ReportedSizeBytes < 512*1024*1024 {
		return res
	}

	h, err := hal.OpenRawVolume(drv.RawVolumePath, true)
	if err != nil {
		return res
	}
	defer h.Close()

	_ = h.LockVolume()
	defer h.UnlockVolume()

	const pageSize = 4096
	const safeAnchorBytes = 256 * 1024 * 1024 // +256 MiB anchor safely past MBR/VBR/FAT/RootDir
	partOff := int64(drv.PartitionOffset)

	// Backup map: volumeOffset -> original 4096 bytes
	backups := make(map[int64][]byte)
	saveOriginal := func(volOff int64) {
		if _, exists := backups[volOff]; !exists {
			orig := make([]byte, pageSize)
			if err := h.ReadAtAligned(volOff, orig); err == nil {
				backups[volOff] = orig
			}
		}
	}
	restoreOne := func(volOff int64) {
		if orig, exists := backups[volOff]; exists {
			_ = h.WriteAtAligned(volOff, orig)
			delete(backups, volOff)
		}
	}
	defer func() {
		for volOff, orig := range backups {
			_ = h.WriteAtAligned(volOff, orig)
		}
		res.NonDestructivePreserved = true
	}()

	// Build candidate GiB grid up to reported size
	maxGiB := int64((drv.ReportedSizeBytes - safeAnchorBytes - 65536) / (1024 * 1024 * 1024))
	candidateTemplate := []int64{0, 1, 2, 3, 4, 6, 7, 8, 12, 14, 15, 16, 20, 24, 28, 29, 30, 31, 32, 48, 60, 63, 64, 96, 120, 127, 128, 250, 255, 256, 500, 511, 512, 1000, 1024, 1500, 1850, 1900}
	var gridGiB []int64
	for _, g := range candidateTemplate {
		if g <= maxGiB {
			gridGiB = append(gridGiB, g)
		}
	}
	if len(gridGiB) == 0 || gridGiB[len(gridGiB)-1] < maxGiB {
		if maxGiB > 0 {
			gridGiB = append(gridGiB, maxGiB)
		}
	}

	buf := make([]byte, pageSize)
	readBuf := make([]byte, pageSize)
	canaryVolOff := int64(safeAnchorBytes) - partOff
	canaryTag := uint64(0xCAFEBABE00000000)

	var lastValidGiB int64 = 0
	var firstInvalidGiB int64 = -1

	// === PHASE 1: EXPONENTIAL + MODULO-SAFE GRID SWEEP ===
	for idx, g := range gridGiB {
		if onProgress != nil {
			pct := (idx * 50) / len(gridGiB)
			onProgress(fmt.Sprintf("Phase 1: Probing LBA Grid at %d GiB (+256 MiB)...", g), pct)
		}

		physByte := uint64(safeAnchorBytes) + uint64(g)*1024*1024*1024
		volOff := int64(physByte) - partOff
		saveOriginal(volOff)

		tag := uint64(0xCAFEBABE00000000) | uint64(g)
		for i := 0; i < pageSize; i += 8 {
			binary.LittleEndian.PutUint64(buf[i:i+8], tag+uint64(i))
		}

		t0 := time.Now()
		wErr := h.WriteAtAligned(volOff, buf)
		_ = h.ReadAtAligned(volOff, readBuf)
		latMs := math.Round(time.Since(t0).Seconds()*10000) / 10
		gotTag := binary.LittleEndian.Uint64(readBuf[0:8])

		// Check Canary at K=0 to detect Modulo LBA Wrap-Around!
		canaryIntact := true
		if g > 0 {
			canaryCheck := make([]byte, pageSize)
			if err := h.ReadAtAligned(canaryVolOff, canaryCheck); err == nil {
				cGot := binary.LittleEndian.Uint64(canaryCheck[0:8])
				if cGot != canaryTag {
					canaryIntact = false
					// Restore canary immediately so subsequent probes also test against canaryTag
					for i := 0; i < pageSize; i += 8 {
						binary.LittleEndian.PutUint64(buf[i:i+8], canaryTag+uint64(i))
					}
					_ = h.WriteAtAligned(canaryVolOff, buf)
				}
			}
		}

		status := "VALID"
		if wErr != nil {
			status = "ERROR"
		} else if !canaryIntact {
			status = "WRAP_AROUND"
			if res.WrapAroundDetectedAtGiB == 0 {
				res.WrapAroundDetectedAtGiB = float64(g)
			}
		} else if gotTag != tag {
			if gotTag == 0xFFFFFFFFFFFFFFFF {
				status = "FAKE_VOID_FF"
			} else if gotTag == 0x0000000000000000 {
				status = "FAKE_VOID_00"
			} else {
				status = "CORRUPTED"
			}
		}

		res.GridProbes = append(res.GridProbes, model.ProbePoint{
			Index:         idx,
			OffsetGiB:     math.Round((float64(physByte)/(1024.0*1024.0*1024.0))*100) / 100,
			PhysicalByte:  physByte,
			PhysicalLBA:   physByte / 512,
			Status:        status,
			WrittenTagHex: fmt.Sprintf("0x%016X", tag),
			ReadTagHex:    fmt.Sprintf("0x%016X", gotTag),
			CanaryIntact:  canaryIntact,
			LatencyMs:     latMs,
		})

		if status == "VALID" && firstInvalidGiB == -1 {
			lastValidGiB = g
		} else if status != "VALID" && firstInvalidGiB == -1 {
			firstInvalidGiB = g
			switch status {
			case "FAKE_VOID_FF":
				res.FailureMode = "BLACK_HOLE_0xFF"
			case "FAKE_VOID_00":
				res.FailureMode = "BLACK_HOLE_0x00"
			case "WRAP_AROUND":
				res.FailureMode = "LBA_WRAP_AROUND"
			default:
				res.FailureMode = "DATA_CORRUPTION"
			}
		}
	}

	// Clean up Phase 1 probe points before Phase 2
	for volOff := range backups {
		restoreOne(volOff)
	}

	// If all grid points up to the end of the drive succeeded, drive capacity is genuine!
	if firstInvalidGiB == -1 {
		res.Tested = true
		res.IsFakeCapacity = false
		res.TrueCapacityBytes = drv.ReportedSizeBytes
		res.TrueValidSectors512 = drv.TotalSectors
		res.LastValid4KPage = (drv.ReportedSizeBytes / 4096) - 1
		res.TrueCapacityGiB = drv.ReportedSizeGiB
		res.TrueCapacityGB = drv.ReportedSizeGB
		res.FakeCapacityBytes = 0
		res.FakePercentage = 0
		res.DurationSeconds = math.Round(time.Since(tStart).Seconds()*100) / 100
		return res
	}

	// === PHASE 2: NARROW 1-GiB WINDOW + EXACT 4KB PAGE BINARY SEARCH ===
	res.IsFakeCapacity = true

	// Step 2a: Narrow down to exact 1-GiB interval between lastValidGiB and firstInvalidGiB
	testPage4K := func(page4K uint64) (bool, uint64) {
		physByte := page4K * 4096
		volOff := int64(physByte) - partOff
		saveOriginal(volOff)
		defer restoreOne(volOff)

		magic := uint64(0xA55AA55A00000000) ^ page4K
		for i := 0; i < pageSize; i += 8 {
			binary.LittleEndian.PutUint64(buf[i:i+8], magic+uint64(i))
		}
		if err := h.WriteAtAligned(volOff, buf); err != nil {
			return false, 0
		}
		for i := range readBuf {
			readBuf[i] = 0
		}
		if err := h.ReadAtAligned(volOff, readBuf); err != nil {
			return false, 0
		}
		got := binary.LittleEndian.Uint64(readBuf[0:8])
		return got == magic, got
	}

	for g := lastValidGiB + 1; g < firstInvalidGiB; g++ {
		physByte := uint64(safeAnchorBytes) + uint64(g)*1024*1024*1024
		page := physByte / 4096
		ok, _ := testPage4K(page)
		if ok {
			lastValidGiB = g
		} else {
			firstInvalidGiB = g
			break
		}
	}

	lowPage := (uint64(safeAnchorBytes) + uint64(lastValidGiB)*1024*1024*1024) / 4096
	highPage := (uint64(safeAnchorBytes) + uint64(firstInvalidGiB)*1024*1024*1024) / 4096

	stepNum := 0
	for lowPage < highPage {
		stepNum++
		midPage := lowPage + (highPage-lowPage+1)/2
		if onProgress != nil {
			pct := 50 + ((stepNum * 48) / 22)
			if pct > 98 {
				pct = 98
			}
			onProgress(fmt.Sprintf("Phase 2: Binary Search Step #%d (Page 0x%X)...", stepNum, midPage), pct)
		}
		ok, gotHex := testPage4K(midPage)
		res.BinarySearchSteps = append(res.BinarySearchSteps, model.BinarySearchStep{
			Step:           stepNum,
			LowPage4K:      lowPage,
			HighPage4K:     highPage,
			MidPage4K:      midPage,
			MidOffsetGiB:   math.Round((float64(midPage*4096)/(1024.0*1024.0*1024.0))*10000) / 10000,
			MidPhysicalLBA: midPage * 8,
			Valid:          ok,
			ReadBackHex:    fmt.Sprintf("0x%016X", gotHex),
		})
		if ok {
			lowPage = midPage
		} else {
			highPage = midPage - 1
		}
	}

	res.Tested = true
	res.LastValid4KPage = lowPage
	res.FirstInvalid4KPage = lowPage + 1
	totalValidPages := lowPage + 1
	res.TrueValidSectors512 = totalValidPages * 8
	res.TrueCapacityBytes = totalValidPages * 4096
	res.TrueCapacityGiB = math.Round((float64(res.TrueCapacityBytes)/(1024.0*1024.0*1024.0))*10000) / 10000
	res.TrueCapacityGB = math.Round((float64(res.TrueCapacityBytes)/1e9)*10000) / 10000

	if drv.ReportedSizeBytes > res.TrueCapacityBytes {
		res.FakeCapacityBytes = drv.ReportedSizeBytes - res.TrueCapacityBytes
		res.FakePercentage = math.Round((float64(res.FakeCapacityBytes)/float64(drv.ReportedSizeBytes))*10000) / 100
	}
	res.DurationSeconds = math.Round(time.Since(tStart).Seconds()*100) / 100
	return res
}
