package forensics

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// SDCIDInfo represents the decoded fields of a 128-bit SD / microSD / eMMC Card Identification (CID) Register.
type SDCIDInfo struct {
	RawCIDHex        string `json:"raw_cid_hex"`
	Valid            bool   `json:"valid"`
	ManufacturerID   byte   `json:"manufacturer_id"`   // MID (Byte 0)
	ManufacturerName string `json:"manufacturer_name"` // Resolved OEM Brand
	OEMApplicationID string `json:"oem_application_id"`// OID (Bytes 1..2 ASCII)
	ProductName      string `json:"product_name"`      // PNM (Bytes 3..7 ASCII)
	ProductRevision  string `json:"product_revision"`  // PRV (Byte 8 BCD Major.Minor)
	ProductSerial    uint32 `json:"product_serial"`    // PSN (Bytes 9..12 Big-Endian)
	ManufactureDate  string `json:"manufacture_date"`  // MDT (Bytes 13..14 Year-Month)
	CRC7Expected     byte   `json:"crc7_expected"`
	CRC7Actual       byte   `json:"crc7_actual"`
	CRC7Valid        bool   `json:"crc7_valid"`
}

var sdMIDRegistry = map[byte]string{
	0x01: "Panasonic",
	0x02: "Toshiba / Kioxia / Kingston",
	0x03: "SanDisk Corporation (Western Digital)",
	0x09: "ATP Electronics",
	0x13: "Kingmax",
	0x19: "Dynacard",
	0x1B: "Samsung Electronics Co., Ltd.",
	0x1D: "ADATA Technology",
	0x27: "Phison Electronics Corp. (OEM)",
	0x28: "Barun Electronics / Lexar OEM",
	0x31: "Silicon Power",
	0x41: "Kingston Technology",
	0x74: "Transcend Information",
	0x76: "Patriot Memory",
	0x82: "Sony / Jiangtay",
	0x9C: "Angelbird / Hoodman",
}

// ComputeSDCRC7 computes the 7-bit SD specification CRC7 (polynomial x^7 + x^3 + 1 = 0x09) over the first 15 bytes of CID/CSD.
func ComputeSDCRC7(data15 []byte) byte {
	var crc byte
	for _, b := range data15 {
		for bit := 7; bit >= 0; bit-- {
			crc <<= 1
			if ((b >> uint(bit)) & 1) ^ ((crc >> 7) & 1) != 0 {
				crc ^= 0x09
			}
		}
	}
	return crc & 0x7F
}

// DecodeSDCID parses and verifies a 128-bit (16-byte / 32-hex-char) SD Card Identification Register.
func DecodeSDCID(cidHex string) SDCIDInfo {
	clean := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(cidHex), " ", ""), "-", ""))
	raw, err := hex.DecodeString(clean)
	if err != nil || len(raw) != 16 {
		return SDCIDInfo{RawCIDHex: clean, Valid: false}
	}

	mid := raw[0]
	maker, ok := sdMIDRegistry[mid]
	if !ok {
		maker = fmt.Sprintf("Unregistered / Generic Factory MID (0x%02X)", mid)
	}

	oid := sanitizeASCII(raw[1:3])
	pnm := sanitizeASCII(raw[3:8])
	prvMajor := (raw[8] >> 4) & 0x0F
	prvMinor := raw[8] & 0x0F
	psn := binary.BigEndian.Uint32(raw[9:13])

	// MDT is 12 bits across raw[13] (low 4 bits) and raw[14] (8 bits)
	mdtRaw := (uint16(raw[13]&0x0F) << 8) | uint16(raw[14])
	year := 2000 + int((mdtRaw>>4)&0xFF)
	month := int(mdtRaw & 0x0F)
	if month < 1 || month > 12 {
		month = 1
	}

	actualCRC := (raw[15] >> 1) & 0x7F
	expectedCRC := ComputeSDCRC7(raw[0:15])

	return SDCIDInfo{
		RawCIDHex:        clean,
		Valid:            true,
		ManufacturerID:   mid,
		ManufacturerName: maker,
		OEMApplicationID: oid,
		ProductName:      pnm,
		ProductRevision:  fmt.Sprintf("%d.%d", prvMajor, prvMinor),
		ProductSerial:    psn,
		ManufactureDate:  fmt.Sprintf("%04d-%02d", year, month),
		CRC7Expected:     expectedCRC,
		CRC7Actual:       actualCRC,
		CRC7Valid:        actualCRC == expectedCRC && (raw[15]&0x01) == 1,
	}
}

func sanitizeASCII(b []byte) string {
	var out strings.Builder
	for _, c := range b {
		if c >= 32 && c < 127 {
			out.WriteByte(c)
		}
	}
	return strings.TrimSpace(out.String())
}
