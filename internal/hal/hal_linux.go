//go:build linux

package hal

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/flashtruth/flashtruth/internal/model"
)

const (
	oDirect = 0x4000 // O_DIRECT on Linux x86_64/arm64
	sgIO    = 0x2285 // SG_IO ioctl
)

type linuxRawHandle struct {
	fd         int
	alignedBuf []byte
	alignedOff int
}

// OpenRawVolume opens a block device (e.g. "/dev/sdb1" or "/dev/sdb") on Linux with O_DIRECT | O_SYNC.
func OpenRawVolume(rawPath string, writable bool) (RawDeviceHandle, error) {
	flags := syscall.O_RDONLY | syscall.O_SYNC | oDirect
	if writable {
		flags = syscall.O_RDWR | syscall.O_SYNC | oDirect
	}
	fd, err := syscall.Open(rawPath, flags, 0600)
	if err != nil {
		// Fallback without O_DIRECT if filesystem/architecture differs
		flags &^= oDirect
		fd, err = syscall.Open(rawPath, flags, 0600)
		if err != nil {
			return nil, fmt.Errorf("open(%s) failed: %w", rawPath, err)
		}
	}
	// Allocate 1MB + 4096 bytes and align slice start to 4096-byte page boundary
	raw := make([]byte, (1024*1024)+4096)
	ptr := uintptr(unsafe.Pointer(&raw[0]))
	rem := int(ptr % 4096)
	off := 0
	if rem != 0 {
		off = 4096 - rem
	}
	return &linuxRawHandle{
		fd:         fd,
		alignedBuf: raw,
		alignedOff: off,
	}, nil
}

func (l *linuxRawHandle) slice(n int) []byte {
	return l.alignedBuf[l.alignedOff : l.alignedOff+n]
}

func (l *linuxRawHandle) LockVolume() error {
	return syscall.Flock(l.fd, syscall.LOCK_EX|syscall.LOCK_NB)
}

func (l *linuxRawHandle) UnlockVolume() error {
	return syscall.Flock(l.fd, syscall.LOCK_UN)
}

func (l *linuxRawHandle) ReadAtAligned(offset int64, buf []byte) error {
	aligned := l.slice(len(buf))
	n, err := syscall.Pread(l.fd, aligned, offset)
	if err != nil || n != len(buf) {
		return fmt.Errorf("pread at %d failed (n=%d): %v", offset, n, err)
	}
	copy(buf, aligned)
	return nil
}

func (l *linuxRawHandle) WriteAtAligned(offset int64, buf []byte) error {
	aligned := l.slice(len(buf))
	copy(aligned, buf)
	n, err := syscall.Pwrite(l.fd, aligned, offset)
	if err != nil || n != len(buf) {
		return fmt.Errorf("pwrite at %d failed (n=%d): %v", offset, n, err)
	}
	_ = syscall.Fsync(l.fd)
	return nil
}

func (l *linuxRawHandle) Close() error {
	_ = l.UnlockVolume()
	return syscall.Close(l.fd)
}

type sgIoHdr struct {
	InterfaceID    int32
	DxferDirection int32
	CmdLen         uint8
	MxSbLen        uint8
	IovecCount     uint16
	DxferLen       uint32
	Dxferp         uintptr
	Cmdp           uintptr
	Sbp            uintptr
	Timeout        uint32
	Flags          uint32
	PackID         int32
	UsrPtr         uintptr
	Status         uint8
	MaskedStatus   uint8
	MsgStatus      uint8
	SbLenWr        uint8
	HostStatus     uint16
	DriverStatus   uint16
	Resid          int32
	Duration       uint32
	Info           uint32
}

// QuerySCSI sends SCSI INQUIRY and READ CAPACITY(10) via Linux SG_IO ioctl.
func QuerySCSI(rawVolumePath string) model.SCSIFingerprint {
	var res model.SCSIFingerprint
	fd, err := syscall.Open(rawVolumePath, syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return res
	}
	defer syscall.Close(fd)

	inqBuf := make([]byte, 96)
	if ok := sendLinuxSGIO(fd, []byte{0x12, 0, 0, 0, 96, 0}, inqBuf); ok {
		res.Supported = true
		res.InquiryHex = strings.ToUpper(hex.EncodeToString(inqBuf[:36]))
		var ascii strings.Builder
		for _, b := range inqBuf[:36] {
			if b >= 32 && b < 127 {
				ascii.WriteByte(b)
			} else {
				ascii.WriteByte('.')
			}
		}
		res.InquiryASCII = ascii.String()
		res.VendorID8 = strings.TrimSpace(string(inqBuf[8:16]))
		res.ProductID16 = strings.TrimSpace(string(inqBuf[16:32]))
		res.ProductRev4 = strings.TrimSpace(string(inqBuf[32:36]))
	}

	capBuf := make([]byte, 8)
	if ok := sendLinuxSGIO(fd, []byte{0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0}, capBuf); ok {
		res.Supported = true
		res.ReadCapacityHex = strings.ToUpper(hex.EncodeToString(capBuf))
		lastLBA := binary.BigEndian.Uint32(capBuf[0:4])
		secSize := binary.BigEndian.Uint32(capBuf[4:8])
		res.ReportedLastLBA = uint64(lastLBA)
		res.ReportedTotalSectors = uint64(lastLBA) + 1
		res.ReportedSectorSize = secSize
		res.IsSyntheticMPtoolRound, res.SyntheticFormulaNote = CheckSyntheticMPtoolCapacity(res.ReportedTotalSectors, secSize)
	}
	return res
}

func sendLinuxSGIO(fd int, cdb []byte, data []byte) bool {
	sense := make([]byte, 32)
	hdr := sgIoHdr{
		InterfaceID:    'S',
		DxferDirection: -3, // SG_DXFER_FROM_DEV
		CmdLen:         uint8(len(cdb)),
		MxSbLen:        uint8(len(sense)),
		DxferLen:       uint32(len(data)),
		Dxferp:         uintptr(unsafe.Pointer(&data[0])),
		Cmdp:           uintptr(unsafe.Pointer(&cdb[0])),
		Sbp:            uintptr(unsafe.Pointer(&sense[0])),
		Timeout:        5000,
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(sgIO), uintptr(unsafe.Pointer(&hdr)))
	return errno == 0 && hdr.Status == 0
}

func readSysFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func ListDrives() ([]model.DriveInfo, error) {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}
	var drives []model.DriveInfo
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "sd") && !strings.HasPrefix(name, "mmcblk") {
			continue
		}
		rem := readSysFile(filepath.Join("/sys/block", name, "removable"))
		if rem != "1" {
			continue
		}
		d, _, _, err := InspectDriveHardware("/dev/" + name)
		if err == nil {
			drives = append(drives, d)
		}
	}
	return drives, nil
}

func InspectDriveHardware(targetDrive string) (model.DriveInfo, model.USBTopology, string, error) {
	base := filepath.Base(targetDrive)
	parentBlock := strings.TrimRight(base, "0123456789")
	sysBlock := filepath.Join("/sys/block", parentBlock)

	sectors, _ := strconv.ParseUint(readSysFile(filepath.Join(sysBlock, "size")), 10, 64)
	secBytes := uint64(512)
	totBytes := sectors * secBytes

	partStartLBA := uint64(0)
	rawVolPath := "/dev/" + base
	partDir := filepath.Join(sysBlock, base+"1")
	if st, err := os.Stat(partDir); err == nil && st.IsDir() {
		rawVolPath = "/dev/" + base + "1"
		partStartLBA, _ = strconv.ParseUint(readSysFile(filepath.Join(partDir, "start")), 10, 64)
	}

	drv := model.DriveInfo{
		DevicePath:        targetDrive,
		RawVolumePath:     rawVolPath,
		PhysicalDiskPath:  "/dev/" + parentBlock,
		BytesPerSector:    512,
		TotalSectors:      sectors,
		ReportedSizeBytes: totBytes,
		ReportedSizeGiB:   float64(totBytes) / (1024.0 * 1024.0 * 1024.0),
		ReportedSizeGB:    float64(totBytes) / 1e9,
		PartitionOffset:   partStartLBA * 512,
		PartitionStartLBA: partStartLBA,
		PartitionStyle:    "MBR",
		IsRemovable:       true,
	}

	var usb model.USBTopology
	devLink, err := filepath.EvalSymlinks(filepath.Join(sysBlock, "device"))
	if err == nil {
		cur := devLink
		for i := 0; i < 6; i++ {
			vid := readSysFile(filepath.Join(cur, "idVendor"))
			pid := readSysFile(filepath.Join(cur, "idProduct"))
			if vid != "" && pid != "" {
				usb.VendorID = strings.ToUpper(vid)
				usb.ProductID = strings.ToUpper(pid)
				usb.Revision = readSysFile(filepath.Join(cur, "bcdDevice"))
				usb.SerialNumber = readSysFile(filepath.Join(cur, "serial"))
				usb.ManufacturerString = readSysFile(filepath.Join(cur, "manufacturer"))
				usb.ProductString = readSysFile(filepath.Join(cur, "product"))
				spd := readSysFile(filepath.Join(cur, "speed"))
				if spd == "480" || spd == "12" {
					usb.NegotiatedSpeed = fmt.Sprintf("High-Speed (USB 2.0 - %s Mbps)", spd)
				} else if spd != "" {
					usb.NegotiatedSpeed = fmt.Sprintf("SuperSpeed (USB 3.x - %s Mbps)", spd)
				}
				break
			}
			cur = filepath.Dir(cur)
		}
	}

	var mbrHex string
	if f, err := os.Open("/dev/" + parentBlock); err == nil {
		mbr := make([]byte, 512)
		if n, _ := f.Read(mbr); n == 512 {
			mbrHex = strings.ToUpper(hex.EncodeToString(mbr))
		}
		f.Close()
	}
	return drv, usb, mbrHex, nil
}
