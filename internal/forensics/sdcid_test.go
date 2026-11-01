package forensics

import (
	"encoding/hex"
	"testing"
)

func TestDecodeSDCID(t *testing.T) {
	// Construct a valid SanDisk (0x03) SD CID register with valid CRC7
	raw := []byte{
		0x03,       // MID = 0x03 (SanDisk)
		'S', 'D',   // OID = "SD"
		'S', 'L', '3', '2', 'G', // PNM = "SL32G"
		0x80,       // PRV = 8.0
		0x12, 0x34, 0x56, 0x78, // PSN = 0x12345678
		0x01, 0x9B, // MDT = 2025-11
		0x00,
	}
	crc := ComputeSDCRC7(raw[:15])
	raw[15] = (crc << 1) | 0x01

	info := DecodeSDCID(hex.EncodeToString(raw))
	if !info.Valid || !info.CRC7Valid {
		t.Fatalf("expected valid SD CID and CRC7, got Valid=%v CRC7Valid=%v", info.Valid, info.CRC7Valid)
	}
	if info.ManufacturerID != 0x03 || info.OEMApplicationID != "SD" || info.ProductName != "SL32G" {
		t.Fatalf("unexpected decoded CID fields: %+v", info)
	}
	if info.ManufactureDate != "2025-11" {
		t.Fatalf("expected 2025-11, got %s", info.ManufactureDate)
	}
}
