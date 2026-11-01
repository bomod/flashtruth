//go:build darwin

package hal

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/flashtruth/flashtruth/internal/model"
)

const (
	fNoCache   = 48 // F_NOCACHE on macOS XNU
	fFullFsync = 51 // F_FULLFSYNC on macOS XNU
)

type darwinRawHandle struct {
	fd int
}

// OpenRawVolume opens a macOS raw disk character device (e.g. "/dev/rdisk2s1" or "/dev/rdisk2") with F_NOCACHE.
func OpenRawVolume(rawPath string, writable bool) (RawDeviceHandle, error) {
	if strings.HasPrefix(rawPath, "/dev/disk") {
		rawPath = strings.Replace(rawPath, "/dev/disk", "/dev/rdisk", 1)
	}
	flags := syscall.O_RDONLY
	if writable {
		flags = syscall.O_RDWR
	}
	fd, err := syscall.Open(rawPath, flags, 0600)
	if err != nil {
		return nil, fmt.Errorf("open(%s) failed: %w", rawPath, err)
	}
	_, _, _ = syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(fNoCache), 1)
	return &darwinRawHandle{fd: fd}, nil
}

func (d *darwinRawHandle) LockVolume() error {
	return syscall.Flock(d.fd, syscall.LOCK_EX|syscall.LOCK_NB)
}

func (d *darwinRawHandle) UnlockVolume() error {
	return syscall.Flock(d.fd, syscall.LOCK_UN)
}

func (d *darwinRawHandle) ReadAtAligned(offset int64, buf []byte) error {
	n, err := syscall.Pread(d.fd, buf, offset)
	if err != nil || n != len(buf) {
		return fmt.Errorf("pread at %d failed (n=%d): %v", offset, n, err)
	}
	return nil
}

func (d *darwinRawHandle) WriteAtAligned(offset int64, buf []byte) error {
	n, err := syscall.Pwrite(d.fd, buf, offset)
	if err != nil || n != len(buf) {
		return fmt.Errorf("pwrite at %d failed (n=%d): %v", offset, n, err)
	}
	_, _, _ = syscall.Syscall(syscall.SYS_FCNTL, uintptr(d.fd), uintptr(fFullFsync), 0)
	return nil
}

func (d *darwinRawHandle) Close() error {
	_ = d.UnlockVolume()
	return syscall.Close(d.fd)
}

func QuerySCSI(rawVolumePath string) model.SCSIFingerprint {
	return model.SCSIFingerprint{Supported: false}
}

func ListDrives() ([]model.DriveInfo, error) {
	out, err := exec.Command("diskutil", "list", "external", "physical").Output()
	if err != nil {
		return nil, err
	}
	var drives []model.DriveInfo
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "/dev/disk") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				d, _, _, err := InspectDriveHardware(fields[0])
				if err == nil {
					drives = append(drives, d)
				}
			}
		}
	}
	return drives, nil
}

func InspectDriveHardware(targetDrive string) (model.DriveInfo, model.USBTopology, string, error) {
	drv := model.DriveInfo{
		DevicePath:       targetDrive,
		RawVolumePath:    strings.Replace(targetDrive, "/dev/disk", "/dev/rdisk", 1),
		PhysicalDiskPath: targetDrive,
		BytesPerSector:   512,
		IsRemovable:      true,
	}
	var usb model.USBTopology
	var mbrHex string
	if f, err := os.Open(drv.RawVolumePath); err == nil {
		mbr := make([]byte, 512)
		if n, _ := f.Read(mbr); n == 512 {
			mbrHex = strings.ToUpper(hex.EncodeToString(mbr))
		}
		f.Close()
	}
	return drv, usb, mbrHex, nil
}
