package forensics

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/flashtruth/flashtruth/internal/hal"
	"github.com/flashtruth/flashtruth/internal/model"
)

// InspectBootAndRoot analyzes the MBR, the Volume Boot Record (VBR), and the raw Root Directory cluster.
func InspectBootAndRoot(drv model.DriveInfo, mbrHex string) model.BootSectorForensics {
	var res model.BootSectorForensics

	// 1. Parse MBR if available
	if len(mbrHex) >= 1024 {
		mbrBytes, err := hex.DecodeString(mbrHex[:1024])
		if err == nil && len(mbrBytes) == 512 {
			res.Inspected = true
			res.MBRBootstrapHex = strings.ToUpper(hex.EncodeToString(mbrBytes[0:32]))
			res.MBRSignatureHex = strings.ToUpper(hex.EncodeToString(mbrBytes[440:444]))
			part1 := mbrBytes[446:462]
			res.MBRPartitionEntry1Hex = strings.ToUpper(hex.EncodeToString(part1))
			startLBA := binary.LittleEndian.Uint32(part1[8:12])
			if startLBA > 0 && startLBA <= 63 {
				res.IsMPtoolLBA32Layout = true
			}
		}
	}
	if drv.PartitionStartLBA > 0 && drv.PartitionStartLBA <= 63 {
		res.IsMPtoolLBA32Layout = true
	}

	// 2. Open Raw Volume to read VBR and Root Directory cluster
	h, err := hal.OpenRawVolume(drv.RawVolumePath, false)
	if err != nil {
		return res
	}
	defer h.Close()

	vbr := make([]byte, 4096)
	if err := h.ReadAtAligned(0, vbr); err != nil {
		return res
	}
	res.Inspected = true
	res.VBRBootJumpHex = strings.ToUpper(hex.EncodeToString(vbr[0:3]))
	res.VBROEMName = strings.TrimRight(string(vbr[3:11]), "\x00")

	if strings.HasPrefix(res.VBROEMName, "EXFAT") {
		volLen := binary.LittleEndian.Uint64(vbr[72:80])
		clusterHeapOffset := binary.LittleEndian.Uint32(vbr[88:92])
		clusterCount := binary.LittleEndian.Uint32(vbr[92:96])
		rootDirCluster := binary.LittleEndian.Uint32(vbr[96:100])
		bytesPerSecShift := vbr[108]
		secPerClusShift := vbr[109]

		if bytesPerSecShift >= 9 && bytesPerSecShift <= 12 && secPerClusShift <= 16 {
			secSize := uint64(1) << bytesPerSecShift
			clusSize := secSize * (uint64(1) << secPerClusShift)
			res.VBRVolumeLengthSectors = volLen
			res.VBRClusterSize = uint32(clusSize)
			res.VBRClusterCount = clusterCount

			if rootDirCluster >= 2 && clusSize <= 512*1024 {
				rootOffset := (uint64(clusterHeapOffset) * secSize) + (uint64(rootDirCluster-2) * clusSize)
				res.RootDirOffsetBytes = rootOffset

				readSize := int(clusSize)
				if readSize > 65536 {
					readSize = 65536
				}
				rootBuf := make([]byte, readSize)
				if err := h.ReadAtAligned(int64(rootOffset), rootBuf); err == nil {
					for off := 0; off < len(rootBuf); off += 32 {
						entryType := rootBuf[off]
						if entryType == 0x00 {
							break
						}
						inUse := (entryType & 0x80) != 0
						baseType := entryType & 0x7F
						desc := describeExFATEntry(entryType)
						var decodedName string
						if baseType == 0x41 { // File Name entry (0xC1 active, 0x41 deleted)
							u16 := make([]uint16, 15)
							for i := 0; i < 15; i++ {
								u16[i] = binary.LittleEndian.Uint16(rootBuf[off+2+(i*2) : off+4+(i*2)])
							}
							decodedName = strings.TrimRight(string(utf16.Decode(u16)), "\x00")
							if !inUse && !strings.HasPrefix(decodedName, "_antigravity") && !strings.HasPrefix(decodedName, "_hw_") && !strings.HasPrefix(decodedName, "_spacer") && !strings.HasPrefix(decodedName, "_flashtruth") {
								res.PriorDeletedFilesCount++
							}
						}
						res.RootDirEntries = append(res.RootDirEntries, model.RawDirectoryEntry{
							Offset:      off,
							EntryType:   fmt.Sprintf("0x%02X", entryType),
							InUse:       inUse,
							Description: desc,
							DecodedName: decodedName,
							RawHex16:    strings.ToUpper(hex.EncodeToString(rootBuf[off : off+16])),
						})
					}
				}
			}
		}
	}

	return res
}

func describeExFATEntry(t byte) string {
	switch t {
	case 0x81:
		return "Allocation Bitmap (Active)"
	case 0x82:
		return "Up-Case Table (Active)"
	case 0x83:
		return "Volume Label (Active)"
	case 0x03:
		return "Empty Volume Label (No Label)"
	case 0x85:
		return "File/Directory Metadata Entry (Active)"
	case 0x05:
		return "File/Directory Metadata Entry (Deleted)"
	case 0xC0:
		return "Stream Extension Entry (Active)"
	case 0x40:
		return "Stream Extension Entry (Deleted)"
	case 0xC1:
		return "File Name Segment (Active)"
	case 0x41:
		return "File Name Segment (Deleted)"
	default:
		return fmt.Sprintf("exFAT Entry 0x%02X", t)
	}
}
