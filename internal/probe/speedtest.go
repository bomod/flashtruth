package probe

import (
	"encoding/binary"
	"math"
	"time"

	"github.com/flashtruth/flashtruth/internal/hal"
	"github.com/flashtruth/flashtruth/internal/model"
)

// RunUnbufferedSpeedTest runs a non-destructive DMA unbuffered hardware read/write benchmark at a safe offset (+192 MiB).
func RunUnbufferedSpeedTest(drv model.DriveInfo, testMB int, onProgress func(string, int)) model.SpeedBenchmark {
	res := model.SpeedBenchmark{
		TestSizeMB: testMB,
	}
	if testMB <= 0 {
		testMB = 16
	}
	if uint64(testMB+256)*1024*1024 > drv.ReportedSizeBytes {
		return res
	}

	h, err := hal.OpenRawVolume(drv.RawVolumePath, true)
	if err != nil {
		return res
	}
	defer h.Close()
	_ = h.LockVolume()
	defer h.UnlockVolume()

	chunkSize := 1024 * 1024 // 1 MB
	basePhysOffset := int64(192*1024*1024) - int64(drv.PartitionOffset)
	if basePhysOffset < 64*1024*1024 {
		basePhysOffset = 128 * 1024 * 1024
	}
	// Align to 4096
	basePhysOffset = (basePhysOffset / 4096) * 4096

	// Backup original chunks so the speed test is 100% non-destructive
	backups := make([][]byte, testMB)
	for m := 0; m < testMB; m++ {
		backups[m] = make([]byte, chunkSize)
		_ = h.ReadAtAligned(basePhysOffset+int64(m*chunkSize), backups[m])
	}
	defer func() {
		for m := 0; m < testMB; m++ {
			_ = h.WriteAtAligned(basePhysOffset+int64(m*chunkSize), backups[m])
		}
	}()

	writeBuf := make([]byte, chunkSize)
	minMs := math.MaxFloat64
	maxMs := 0.0
	var totalWriteSec float64

	for m := 0; m < testMB; m++ {
		if onProgress != nil {
			onProgress("Testing Unbuffered Hardware Write Speed...", (m*50)/testMB)
		}
		for i := 0; i < chunkSize; i += 4 {
			val := uint32((m << 20) ^ i ^ int(0xA5A55A5A))
			binary.LittleEndian.PutUint32(writeBuf[i:i+4], val)
		}
		t0 := time.Now()
		if err := h.WriteAtAligned(basePhysOffset+int64(m*chunkSize), writeBuf); err != nil {
			return res
		}
		elapsed := time.Since(t0).Seconds()
		totalWriteSec += elapsed
		ms := elapsed * 1000.0
		if ms < minMs {
			minMs = ms
		}
		if ms > maxMs {
			maxMs = ms
		}
	}

	readBuf := make([]byte, chunkSize)
	mismatches := 0
	var totalReadSec float64

	for m := 0; m < testMB; m++ {
		if onProgress != nil {
			onProgress("Testing Unbuffered Hardware Read & Integrity...", 50+((m*50)/testMB))
		}
		t0 := time.Now()
		if err := h.ReadAtAligned(basePhysOffset+int64(m*chunkSize), readBuf); err != nil {
			return res
		}
		totalReadSec += time.Since(t0).Seconds()
		for i := 0; i < chunkSize; i += 4 {
			expected := uint32((m << 20) ^ i ^ int(0xA5A55A5A))
			actual := binary.LittleEndian.PutUint32
			_ = actual
			got := binary.LittleEndian.Uint32(readBuf[i : i+4])
			if got != expected {
				mismatches++
			}
		}
	}

	res.Tested = true
	res.WriteTimeSec = math.Round(totalWriteSec*1000) / 1000
	res.ReadTimeSec = math.Round(totalReadSec*1000) / 1000
	if totalWriteSec > 0 {
		res.WriteSpeedMBps = math.Round((float64(testMB)/totalWriteSec)*100) / 100
	}
	if totalReadSec > 0 {
		res.ReadSpeedMBps = math.Round((float64(testMB)/totalReadSec)*100) / 100
	}
	res.MinChunkWriteMs = math.Round(minMs*10) / 10
	res.MaxChunkWriteMs = math.Round(maxMs*10) / 10
	res.AvgChunkWriteMs = math.Round(((totalWriteSec*1000.0)/float64(testMB))*10) / 10
	res.IntegrityVerified = (mismatches == 0)

	switch {
	case res.WriteSpeedMBps < 3.5:
		res.NANDQualityEstimate = "CRITICAL: Degraded / Recycled Scrap QLC/TLC NAND (< 3.5 MB/s true write speed)"
	case res.WriteSpeedMBps < 10.0:
		res.NANDQualityEstimate = "LOW: Budget USB 2.0 Planar NAND (< 10 MB/s write speed)"
	case res.WriteSpeedMBps < 35.0:
		res.NANDQualityEstimate = "STANDARD: Mainstream TLC NAND (10 - 35 MB/s write speed)"
	default:
		res.NANDQualityEstimate = "HIGH: High-Speed USB 3.x / SSD-Grade NAND (> 35 MB/s write speed)"
	}

	return res
}
