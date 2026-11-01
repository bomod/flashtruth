package db

import "testing"

func TestDecodeNANDFlashID(t *testing.T) {
	// Micron 176L / 232L 3D TLC NAND ID: 2C C3 08 32 EA 30
	info := DecodeNANDFlashID("2CC30832EA30")
	if !info.IsAuthentic {
		t.Fatalf("expected Micron 0x2C to be authentic")
	}
	if info.MakerByte != 0x2C || info.DeviceByte != 0xC3 {
		t.Fatalf("unexpected maker/device bytes: %02X %02X", info.MakerByte, info.DeviceByte)
	}
	if info.CellType != "3D TLC (3-bit/cell)" {
		t.Fatalf("expected 3D TLC, got %s", info.CellType)
	}
}

func TestClassifyHDDRecordingTech(t *testing.T) {
	smr := ClassifyHDDRecordingTech("WDC WD40EFAX-68JH4N0", 5400, "HDD")
	if smr.RecordingTech != "SMR (Shingled Magnetic Recording)" {
		t.Fatalf("expected WD40EFAX to be SMR, got %s", smr.RecordingTech)
	}

	cmr := ClassifyHDDRecordingTech("WDC WD40EFZX-68AWUN0", 5400, "HDD")
	if cmr.RecordingTech != "CMR (Conventional Magnetic Recording)" {
		t.Fatalf("expected WD40EFZX to be CMR, got %s", cmr.RecordingTech)
	}

	ssd := ClassifyHDDRecordingTech("NVMe 3500 Micron 1024GB", 0, "SSD")
	if ssd.RecordingTech != "SOLID_STATE" {
		t.Fatalf("expected SSD to be SOLID_STATE, got %s", ssd.RecordingTech)
	}
}

func TestLookupControllerCounterfeit(t *testing.T) {
	sig := LookupController("048D", "1234", "Flash", "Disk 3.0")
	if sig.Category != "KNOWN_FAKE_TEMPLATE" || sig.RiskLevel != "CRITICAL" {
		t.Fatalf("expected 048D:1234 to be KNOWN_FAKE_TEMPLATE/CRITICAL, got %s/%s", sig.Category, sig.RiskLevel)
	}
}
