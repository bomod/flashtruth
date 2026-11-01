package db

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// NANDDieInfo holds decoded physical silicon wafer attributes from a raw 6-to-8 byte ONFI/Toggle NAND Read-ID (0x90).
type NANDDieInfo struct {
	RawIDHex     string `json:"raw_id_hex"`
	MakerByte    byte   `json:"maker_byte"`
	DeviceByte   byte   `json:"device_byte"`
	FoundryName  string `json:"foundry_name"`
	CellType     string `json:"cell_type"`     // SLC, MLC, 3D TLC, 3D QLC
	Generation   string `json:"generation"`    // e.g. BiCS5 112L, Micron B47R 176L, YMTC Xtacking 3.0
	IsAuthentic  bool   `json:"is_authentic"`
}

var nandMakerTable = map[byte]string{
	0x2C: "Micron Technology, Inc. (US Fab)",
	0xB5: "Micron Technology / Spectek",
	0x98: "Kioxia Corporation (formerly Toshiba Memory - Japan Fab)",
	0x45: "SanDisk / Western Digital (BiCS Joint Venture Fab)",
	0xEC: "Samsung Electronics Co., Ltd. (V-NAND Fab)",
	0xAD: "SK Hynix Inc. (4D NAND Fab)",
	0x89: "Intel Corporation / Solidigm",
	0x9B: "Yangtze Memory Technologies Corp. (YMTC Xtacking Fab)",
	0xC8: "GigaDevice Semiconductor",
	0xC2: "Macronix International (MXIC)",
	0xEF: "Winbond Electronics Corp.",
}

// DecodeNANDFlashID decodes a raw hex or byte string from NAND command 0x90 into wafer foundry and cell architecture.
func DecodeNANDFlashID(rawHex string) NANDDieInfo {
	clean := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(rawHex), " ", ""), "-", ""))
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) < 2 {
		return NANDDieInfo{
			RawIDHex:    clean,
			FoundryName: "Unknown / Unreadable NAND ID",
			CellType:    "Unknown",
			Generation:  "N/A",
			IsAuthentic: false,
		}
	}

	maker := b[0]
	dev := b[1]
	foundry, ok := nandMakerTable[maker]
	if !ok {
		foundry = fmt.Sprintf("Unregistered / White-Label Silicon Foundry (0x%02X)", maker)
	}

	cellType := "3D TLC NAND"
	if len(b) >= 3 {
		bitsPerCell := (b[2] >> 2) & 0x03
		switch bitsPerCell {
		case 0:
			cellType = "SLC (1-bit/cell)"
		case 1:
			cellType = "MLC (2-bit/cell)"
		case 2:
			cellType = "3D TLC (3-bit/cell)"
		case 3:
			cellType = "3D QLC (4-bit/cell)"
		}
	}

	gen := fmt.Sprintf("Device Code 0x%02X", dev)
	switch maker {
	case 0x2C, 0xB5:
		if dev == 0xC3 || dev == 0xD3 {
			gen = "Micron B47R / B58R (176L / 232L Replacement-Gate 3D TLC)"
		}
	case 0x98, 0x45:
		gen = fmt.Sprintf("Kioxia / WD BiCS Flash (Device 0x%02X)", dev)
	case 0xEC:
		gen = fmt.Sprintf("Samsung V-NAND (Device 0x%02X)", dev)
	case 0xAD:
		gen = fmt.Sprintf("SK Hynix 4D PUC NAND (Device 0x%02X)", dev)
	case 0x9B:
		gen = fmt.Sprintf("YMTC Xtacking 3D NAND (Device 0x%02X)", dev)
	}

	return NANDDieInfo{
		RawIDHex:    clean,
		MakerByte:   maker,
		DeviceByte:  dev,
		FoundryName: foundry,
		CellType:    cellType,
		Generation:  gen,
		IsAuthentic: ok,
	}
}

// HDDRecordingProfile describes mechanical hard drive recording technology (CMR vs SMR).
type HDDRecordingProfile struct {
	Model          string `json:"model"`
	RecordingTech  string `json:"recording_tech"` // "CMR", "SMR", "SOLID_STATE", "UNKNOWN"
	NominalRPM     uint32 `json:"nominal_rpm"`
	TechnicalNotes string `json:"technical_notes"`
}

var knownSMRPatterns = []string{
	"WD20EFAX", "WD30EFAX", "WD40EFAX", "WD60EFAX", // WD Red DMSMR
	"WD10SPZX", "WD20SPZX", "WD20EZAZ", "WD40EZAZ", "WD60EZAZ", // WD Blue SMR
	"ST2000DM008", "ST3000DM007", "ST4000DM004", "ST6000DM003", "ST8000DM004", // Seagate Barracuda Compute SMR
	"ST5000LM000", "ST4000LM024", // Seagate 2.5" Portable SMR
	"HDWD220", "HDWD240", "HDWD260", "DT02ABA", // Toshiba P300 / DT02 SMR
}

var knownCMRPatterns = []string{
	"WD20EFZX", "WD30EFZX", "WD40EFZX", "WD60EFZX", "WD80EFZZ", // WD Red Plus CMR
	"WD1003FZEX", "WD2003FZEX", "WD4005FZBX", // WD Black CMR
	"ST4000VN008", "ST4000VN006", "ST8000VN004", "ST12000VN0008", // Seagate IronWolf CMR
	"ST16000NM", "ST18000NM", "ST20000NM", // Seagate Exos Enterprise CMR
	"HDWG", "MG08", "MG09", "MG10", // Toshiba N300 / Enterprise MG CMR
}

// ClassifyHDDRecordingTech determines whether a mechanical hard drive uses CMR or SMR recording.
func ClassifyHDDRecordingTech(modelStr string, spindleRPM uint32, mediaType string) HDDRecordingProfile {
	m := strings.ToUpper(strings.TrimSpace(modelStr))
	if strings.ToUpper(mediaType) != "HDD" && spindleRPM == 0 {
		return HDDRecordingProfile{
			Model:          modelStr,
			RecordingTech:  "SOLID_STATE",
			NominalRPM:     0,
			TechnicalNotes: "Non-rotating solid-state storage media (No magnetic platters).",
		}
	}

	for _, smr := range knownSMRPatterns {
		if strings.Contains(m, smr) {
			return HDDRecordingProfile{
				Model:          modelStr,
				RecordingTech:  "SMR (Shingled Magnetic Recording)",
				NominalRPM:     spindleRPM,
				TechnicalNotes: "Drive uses overlapping shingled tracks (SMR); sustained random writes or RAID rebuilds may experience severe latency drops.",
			}
		}
	}

	for _, cmr := range knownCMRPatterns {
		if strings.Contains(m, cmr) {
			return HDDRecordingProfile{
				Model:          modelStr,
				RecordingTech:  "CMR (Conventional Magnetic Recording)",
				NominalRPM:     spindleRPM,
				TechnicalNotes: "Drive uses non-overlapping conventional magnetic tracks (CMR); suitable for NAS/RAID and sustained write workloads.",
			}
		}
	}

	return HDDRecordingProfile{
		Model:          modelStr,
		RecordingTech:  "CMR / Standard Magnetic Recording",
		NominalRPM:     spindleRPM,
		TechnicalNotes: "Standard mechanical rotational hard disk drive.",
	}
}
