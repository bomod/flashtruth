//go:build windows

package hal

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"github.com/flashtruth/flashtruth/internal/model"
)

const (
	genericRead             = 0x80000000
	genericWrite            = 0x40000000
	fileShareRead           = 0x00000001
	fileShareWrite          = 0x00000002
	openExisting            = 3
	fileFlagNoBuffering     = 0x20000000
	fileFlagWriteThrough    = 0x80000000
	fsctlLockVolume         = 0x00090018
	fsctlUnlockVolume       = 0x0009001C
	ioctlScsiPassThroughDir = 0x0004D014
	memCommit               = 0x00001000
	memReserve              = 0x00002000
	memRelease              = 0x00008000
	pageReadWrite           = 0x04
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procCreateFileW      = kernel32.NewProc("CreateFileW")
	procDeviceIoControl  = kernel32.NewProc("DeviceIoControl")
	procSetFilePointerEx = kernel32.NewProc("SetFilePointerEx")
	procReadFile         = kernel32.NewProc("ReadFile")
	procWriteFile        = kernel32.NewProc("WriteFile")
	procVirtualAlloc     = kernel32.NewProc("VirtualAlloc")
	procVirtualFree      = kernel32.NewProc("VirtualFree")
)

type winRawHandle struct {
	handle     syscall.Handle
	alignedPtr uintptr
	alignedCap int
	locked     bool
}

// OpenRawVolume opens a raw volume handle (e.g. "\\.\D:") with FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH.
func OpenRawVolume(rawPath string, writable bool) (RawDeviceHandle, error) {
	if !strings.HasPrefix(rawPath, `\\.\`) {
		rawPath = `\\.\` + strings.TrimSuffix(rawPath, `\`)
	}
	pathPtr, err := syscall.UTF16PtrFromString(rawPath)
	if err != nil {
		return nil, err
	}
	access := uint32(genericRead)
	if writable {
		access |= genericWrite
	}
	flags := uint32(fileFlagNoBuffering | fileFlagWriteThrough)
	r1, _, e1 := procCreateFileW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(access),
		uintptr(fileShareRead|fileShareWrite),
		0,
		uintptr(openExisting),
		uintptr(flags),
		0,
	)
	h := syscall.Handle(r1)
	if h == syscall.InvalidHandle {
		return nil, fmt.Errorf("CreateFileW(%s) failed: %v", rawPath, e1)
	}

	// Allocate 1 MB page-aligned DMA buffer via VirtualAlloc
	bufCap := 1024 * 1024
	ptr, _, eAlloc := procVirtualAlloc.Call(0, uintptr(bufCap), uintptr(memCommit|memReserve), uintptr(pageReadWrite))
	if ptr == 0 {
		syscall.CloseHandle(h)
		return nil, fmt.Errorf("VirtualAlloc failed: %v", eAlloc)
	}

	return &winRawHandle{
		handle:     h,
		alignedPtr: ptr,
		alignedCap: bufCap,
	}, nil
}

func (w *winRawHandle) LockVolume() error {
	var bytesRet uint32
	r1, _, e1 := procDeviceIoControl.Call(
		uintptr(w.handle),
		uintptr(fsctlLockVolume),
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&bytesRet)),
		0,
	)
	if r1 == 0 {
		return fmt.Errorf("FSCTL_LOCK_VOLUME failed: %v", e1)
	}
	w.locked = true
	return nil
}

func (w *winRawHandle) UnlockVolume() error {
	if !w.locked {
		return nil
	}
	var bytesRet uint32
	r1, _, e1 := procDeviceIoControl.Call(
		uintptr(w.handle),
		uintptr(fsctlUnlockVolume),
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&bytesRet)),
		0,
	)
	w.locked = false
	if r1 == 0 {
		return fmt.Errorf("FSCTL_UNLOCK_VOLUME failed: %v", e1)
	}
	return nil
}

func (w *winRawHandle) seekTo(offset int64) error {
	var newPos int64
	r1, _, e1 := procSetFilePointerEx.Call(
		uintptr(w.handle),
		uintptr(offset),
		uintptr(unsafe.Pointer(&newPos)),
		0,
	)
	if r1 == 0 {
		return fmt.Errorf("SetFilePointerEx(%d) failed: %v", offset, e1)
	}
	return nil
}

func (w *winRawHandle) ReadAtAligned(offset int64, buf []byte) error {
	if len(buf) > w.alignedCap {
		return fmt.Errorf("buffer size %d exceeds aligned DMA buffer %d", len(buf), w.alignedCap)
	}
	if err := w.seekTo(offset); err != nil {
		return err
	}
	var bytesRead uint32
	r1, _, e1 := procReadFile.Call(
		uintptr(w.handle),
		w.alignedPtr,
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&bytesRead)),
		0,
	)
	if r1 == 0 || int(bytesRead) != len(buf) {
		return fmt.Errorf("ReadFile at %d failed (read=%d): %v", offset, bytesRead, e1)
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(w.alignedPtr)), len(buf))
	copy(buf, src)
	return nil
}

func (w *winRawHandle) WriteAtAligned(offset int64, buf []byte) error {
	if len(buf) > w.alignedCap {
		return fmt.Errorf("buffer size %d exceeds aligned DMA buffer %d", len(buf), w.alignedCap)
	}
	if err := w.seekTo(offset); err != nil {
		return err
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(w.alignedPtr)), len(buf))
	copy(dst, buf)
	var bytesWritten uint32
	r1, _, e1 := procWriteFile.Call(
		uintptr(w.handle),
		w.alignedPtr,
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&bytesWritten)),
		0,
	)
	if r1 == 0 || int(bytesWritten) != len(buf) {
		return fmt.Errorf("WriteFile at %d failed (written=%d): %v", offset, bytesWritten, e1)
	}
	return nil
}

func (w *winRawHandle) Close() error {
	_ = w.UnlockVolume()
	if w.alignedPtr != 0 {
		procVirtualFree.Call(w.alignedPtr, 0, uintptr(memRelease))
		w.alignedPtr = 0
	}
	if w.handle != syscall.InvalidHandle && w.handle != 0 {
		syscall.CloseHandle(w.handle)
		w.handle = syscall.InvalidHandle
	}
	return nil
}

// scsiPassThroughDirect matches the exact Windows x64 C layout (56 bytes) in ntddscsi.h.
type scsiPassThroughDirect struct {
	Length             uint16
	ScsiStatus         byte
	PathId             byte
	TargetId           byte
	Lun                byte
	CdbLength          byte
	SenseInfoLength    byte
	DataIn             byte
	DataTransferLength uint32
	TimeOutValue       uint32
	DataBuffer         uintptr
	SenseInfoOffset    uint32
	Cdb                [16]byte
}

type scsiPassThroughDirectWithBuffer struct {
	sptd     scsiPassThroughDirect
	Filler   uint32
	SenseBuf [32]byte
}

// QuerySCSI sends raw SCSI INQUIRY (0x12) and READ CAPACITY(10) (0x25) to the volume handle.
func QuerySCSI(rawVolumePath string) model.SCSIFingerprint {
	var res model.SCSIFingerprint
	if rawVolumePath == "" {
		return res
	}
	if !strings.HasPrefix(rawVolumePath, `\\.\`) {
		rawVolumePath = `\\.\` + strings.TrimSuffix(rawVolumePath, `\`)
	}
	pathPtr, err := syscall.UTF16PtrFromString(rawVolumePath)
	if err != nil {
		return res
	}
	r1, _, _ := procCreateFileW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(genericRead|genericWrite),
		uintptr(fileShareRead|fileShareWrite),
		0,
		uintptr(openExisting),
		0,
		0,
	)
	h := syscall.Handle(r1)
	if h == syscall.InvalidHandle {
		return res
	}
	defer syscall.CloseHandle(h)

	// 1. SCSI INQUIRY (0x12)
	inqBuf := make([]byte, 96)
	if n, status, ok := sendSCSICDB(h, []byte{0x12, 0, 0, 0, 96, 0}, inqBuf); ok && status == 0 && n >= 36 {
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

	// 2. SCSI READ CAPACITY(10) (0x25)
	capBuf := make([]byte, 8)
	if n, status, ok := sendSCSICDB(h, []byte{0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0}, capBuf); ok && status == 0 && n == 8 {
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

func sendSCSICDB(h syscall.Handle, cdb []byte, dataBuf []byte) (uint32, byte, bool) {
	var pkt scsiPassThroughDirectWithBuffer
	pkt.sptd.Length = uint16(unsafe.Sizeof(pkt.sptd))
	pkt.sptd.CdbLength = byte(len(cdb))
	pkt.sptd.SenseInfoLength = 32
	pkt.sptd.DataIn = 1 // SCSI_IOCTL_DATA_IN
	pkt.sptd.DataTransferLength = uint32(len(dataBuf))
	pkt.sptd.TimeOutValue = 5
	pkt.sptd.DataBuffer = uintptr(unsafe.Pointer(&dataBuf[0]))
	pkt.sptd.SenseInfoOffset = uint32(unsafe.Offsetof(pkt.SenseBuf))
	copy(pkt.sptd.Cdb[:], cdb)

	var returned uint32
	r1, _, _ := procDeviceIoControl.Call(
		uintptr(h),
		uintptr(ioctlScsiPassThroughDir),
		uintptr(unsafe.Pointer(&pkt)),
		uintptr(unsafe.Sizeof(pkt)),
		uintptr(unsafe.Pointer(&pkt)),
		uintptr(unsafe.Sizeof(pkt)),
		uintptr(unsafe.Pointer(&returned)),
		0,
	)
	return pkt.sptd.DataTransferLength, pkt.sptd.ScsiStatus, r1 != 0
}

// ListDrives enumerates connected storage volumes (USB, NVMe, SATA SSD, HDD, SD) on Windows, sorting removable/USB drives first.
func ListDrives() ([]model.DriveInfo, error) {
	psScript := `
$vols = Get-Volume | Where-Object { $_.DriveLetter -ne $null }
$out = @()
foreach ($v in $vols) {
    $dl = [string]$v.DriveLetter
    $part = Get-Partition -DriveLetter $dl -ErrorAction SilentlyContinue
    $disk = $null
    $pd = $null
    if ($part) {
        $disk = Get-Disk -Number $part.DiskNumber -ErrorAction SilentlyContinue
        $pd = Get-PhysicalDisk -DeviceNumber $part.DiskNumber -ErrorAction SilentlyContinue
    }
    $isUsbOrRem = ($v.DriveType -eq 'Removable') -or ($disk -and $disk.BusType -eq 'USB')
    $isSysBoot = if ($disk -and ($disk.IsBoot -or $disk.IsSystem)) { $true } else { $dl -eq 'C' }
    $wmiVol = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${dl}:'" -ErrorAction SilentlyContinue
    $secSize = if ($disk -and $disk.LogicalSectorSize) { [uint32]$disk.LogicalSectorSize } else { 512 }
    $totSize = if ($part -and $part.Size -gt 0) { [uint64]$part.Size } elseif ($v.Size -gt 0) { [uint64]$v.Size } elseif ($disk -and $disk.Size) { [uint64]$disk.Size } else { 0 }
    $partOff = if ($part) { [uint64]$part.Offset } else { 0 }
    $busType = if ($pd -and $pd.BusType) { [string]$pd.BusType } elseif ($disk) { [string]$disk.BusType } else { "USB" }
    $mediaType = if ($pd -and $pd.MediaType -and $pd.MediaType -ne 'Unspecified') { [string]$pd.MediaType } elseif ($isUsbOrRem) { "Removable Flash" } else { "SSD" }
    $hwModel = if ($pd -and $pd.FriendlyName) { [string]$pd.FriendlyName.Trim() } elseif ($disk -and $disk.FriendlyName) { [string]$disk.FriendlyName.Trim() } else { "" }
    $hwSerial = if ($pd -and $pd.SerialNumber) { [string]$pd.SerialNumber.Trim() } elseif ($disk -and $disk.SerialNumber) { [string]$disk.SerialNumber.Trim() } else { "" }
    $fwVer = if ($pd -and $pd.FirmwareVersion) { [string]$pd.FirmwareVersion.Trim() } elseif ($disk -and $disk.FirmwareVersion) { [string]$disk.FirmwareVersion.Trim() } else { "" }
    $spindle = if ($pd -and $pd.SpindleSpeed) { [uint32]$pd.SpindleSpeed } else { [uint32]0 }
    $health = if ($pd -and $pd.HealthStatus) { [string]$pd.HealthStatus } else { "Healthy" }
    $out += [PSCustomObject]@{
        device_path = "${dl}:"
        raw_volume_path = "\\.\${dl}:"
        physical_disk_path = if ($part) { "\\.\PhysicalDrive$($part.DiskNumber)" } else { "" }
        disk_number = if ($part) { [int]$part.DiskNumber } else { -1 }
        volume_label = [string]$v.FileSystemLabel
        file_system = [string]$v.FileSystem
        volume_serial_number = if ($wmiVol) { [string]$wmiVol.VolumeSerialNumber } else { "" }
        reported_size_bytes = $totSize
        free_space_bytes = [uint64]$v.SizeRemaining
        bytes_per_sector = $secSize
        allocation_unit_size = [uint32]$v.AllocationUnitSize
        total_sectors = [uint64]($totSize / $secSize)
        partition_style = if ($disk) { [string]$disk.PartitionStyle } else { "MBR" }
        partition_offset = $partOff
        partition_start_lba = [uint64]($partOff / $secSize)
        partition_active = if ($part -and $part.IsActive) { $true } else { $false }
        is_removable = [bool]$isUsbOrRem
        is_system_boot = [bool]$isSysBoot
        bus_type = $busType
        media_type = $mediaType
        spindle_speed = $spindle
        firmware_version = $fwVer
        hardware_model = $hwModel
        hardware_serial = $hwSerial
        health_status = $health
    }
}
$out | Sort-Object -Property @{Expression={$_.is_removable}; Descending=$true}, @{Expression={$_.device_path}; Ascending=$true} | ConvertTo-Json -Compress
`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	rawOut, err := cmd.Output()
	if err != nil || len(strings.TrimSpace(string(rawOut))) == 0 {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(rawOut))
	var list []model.DriveInfo
	if strings.HasPrefix(trimmed, "[") {
		_ = json.Unmarshal([]byte(trimmed), &list)
	} else {
		var single model.DriveInfo
		if err := json.Unmarshal([]byte(trimmed), &single); err == nil {
			list = append(list, single)
		}
	}
	for i := range list {
		list[i].ReportedSizeGiB = float64(list[i].ReportedSizeBytes) / (1024.0 * 1024.0 * 1024.0)
		list[i].ReportedSizeGB = float64(list[i].ReportedSizeBytes) / 1e9
	}
	return list, nil
}

// InspectDriveHardware extracts DriveInfo, USBTopology, and Partition Diagnostic MBR hex for a target drive letter (e.g. "D:").
func InspectDriveHardware(targetDrive string) (model.DriveInfo, model.USBTopology, string, error) {
	dl := strings.TrimSuffix(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(targetDrive)), `\\.\`), `:`)
	psScript := fmt.Sprintf(`
$dl = '%s'
$v = Get-Volume -DriveLetter $dl -ErrorAction Stop
$part = Get-Partition -DriveLetter $dl -ErrorAction SilentlyContinue
$disk = if ($part) { Get-Disk -Number $part.DiskNumber -ErrorAction SilentlyContinue } else { $null }
$pd = if ($part) { Get-PhysicalDisk -DeviceNumber $part.DiskNumber -ErrorAction SilentlyContinue } else { $null }
$wmiVol = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${dl}:'" -ErrorAction SilentlyContinue
$wmiDisk = if ($part) { Get-CimInstance Win32_DiskDrive -Filter "Index=$($part.DiskNumber)" -ErrorAction SilentlyContinue } else { $null }

$pnpDiskId = if ($wmiDisk) { [string]$wmiDisk.PNPDeviceID } else { "" }
$parentUsbId = ""
$biosName = ""
$firstInstall = ""
$parentHub = ""
$vid = ""
$pidVal = ""
$rev = ""
$serial = if ($pd -and $pd.SerialNumber) { [string]$pd.SerialNumber.Trim() } elseif ($disk) { [string]$disk.SerialNumber.Trim() } else { "" }

if ($pnpDiskId) {
    $parentProp = Get-PnpDeviceProperty -InstanceId $pnpDiskId -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue
    if ($parentProp -and $parentProp.Data) {
        $parentUsbId = [string]$parentProp.Data
        $hwIdsProp = Get-PnpDeviceProperty -InstanceId $parentUsbId -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction SilentlyContinue
        if ($hwIdsProp -and $hwIdsProp.Data) {
            foreach ($h in $hwIdsProp.Data) {
                if ($h -match 'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})(?:&REV_([0-9A-Za-z._]+))?') {
                    $vid = $matches[1].ToUpper()
                    $pidVal = $matches[2].ToUpper()
                    if ($matches[3]) { $rev = $matches[3] }
                    break
                } elseif ($h -match 'VEN_([0-9A-Fa-f]{4})&DEV_([0-9A-Fa-f]{4})') {
                    $vid = $matches[1].ToUpper()
                    $pidVal = $matches[2].ToUpper()
                    break
                }
            }
        }
        $biosProp = Get-PnpDeviceProperty -InstanceId $parentUsbId -KeyName 'DEVPKEY_Device_BiosDeviceName' -ErrorAction SilentlyContinue
        if ($biosProp) { $biosName = [string]$biosProp.Data }
        $hubProp = Get-PnpDeviceProperty -InstanceId $parentUsbId -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue
        if ($hubProp) { $parentHub = [string]$hubProp.Data }
        $instProp = Get-PnpDeviceProperty -InstanceId $parentUsbId -KeyName 'DEVPKEY_Device_FirstInstallDate' -ErrorAction SilentlyContinue
        if ($instProp -and $instProp.Data) { $firstInstall = $instProp.Data.ToString("yyyy-MM-dd HH:mm:ss") }
    }
}

$mbrHex = ""
if ($part) {
    $ev = Get-WinEvent -LogName "Microsoft-Windows-Partition/Diagnostic" -MaxEvents 15 -ErrorAction SilentlyContinue | Where-Object {
        ([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq 'DiskNumber' -and $_.'#text' -eq "$($part.DiskNumber)" }
    } | Select-Object -First 1
    if ($ev) {
        $xml = [xml]$ev.ToXml()
        $mbrNode = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Mbr' }
        if ($mbrNode) { $mbrHex = [string]$mbrNode.'#text' }
    }
}

$secSize = if ($disk -and $disk.LogicalSectorSize) { [uint32]$disk.LogicalSectorSize } else { 512 }
$totSize = if ($part -and $part.Size -gt 0) { [uint64]$part.Size } elseif ($v.Size -gt 0) { [uint64]$v.Size } elseif ($disk -and $disk.Size) { [uint64]$disk.Size } else { 0 }
$partOff = if ($part) { [uint64]$part.Offset } else { 0 }
$isUsbOrRem = ($v.DriveType -eq 'Removable') -or ($disk -and $disk.BusType -eq 'USB')
$isSysBoot = if ($disk -and ($disk.IsBoot -or $disk.IsSystem)) { $true } else { $dl -eq 'C' }
$busType = if ($pd -and $pd.BusType) { [string]$pd.BusType } elseif ($disk) { [string]$disk.BusType } else { "USB" }
$mediaType = if ($pd -and $pd.MediaType -and $pd.MediaType -ne 'Unspecified') { [string]$pd.MediaType } elseif ($isUsbOrRem) { "Removable Flash" } else { "SSD" }
$hwModel = if ($pd -and $pd.FriendlyName) { [string]$pd.FriendlyName.Trim() } elseif ($disk -and $disk.FriendlyName) { [string]$disk.FriendlyName.Trim() } else { "" }
$fwVer = if ($pd -and $pd.FirmwareVersion) { [string]$pd.FirmwareVersion.Trim() } elseif ($disk -and $disk.FirmwareVersion) { [string]$disk.FirmwareVersion.Trim() } else { "" }
$spindle = if ($pd -and $pd.SpindleSpeed) { [uint32]$pd.SpindleSpeed } else { [uint32]0 }
$health = if ($pd -and $pd.HealthStatus) { [string]$pd.HealthStatus } else { "Healthy" }

[PSCustomObject]@{
    Drive = @{
        device_path = "${dl}:"
        raw_volume_path = "\\.\${dl}:"
        physical_disk_path = if ($part) { "\\.\PhysicalDrive$($part.DiskNumber)" } else { "" }
        disk_number = if ($part) { [int]$part.DiskNumber } else { -1 }
        volume_label = [string]$v.FileSystemLabel
        file_system = [string]$v.FileSystem
        volume_serial_number = if ($wmiVol) { [string]$wmiVol.VolumeSerialNumber } else { "" }
        reported_size_bytes = $totSize
        free_space_bytes = [uint64]$v.SizeRemaining
        bytes_per_sector = $secSize
        allocation_unit_size = [uint32]$v.AllocationUnitSize
        total_sectors = [uint64]($totSize / $secSize)
        partition_style = if ($disk) { [string]$disk.PartitionStyle } else { "MBR" }
        partition_offset = $partOff
        partition_start_lba = [uint64]($partOff / $secSize)
        partition_active = if ($part -and $part.IsActive) { $true } else { $false }
        is_removable = [bool]$isUsbOrRem
        is_system_boot = [bool]$isSysBoot
        bus_type = $busType
        media_type = $mediaType
        spindle_speed = $spindle
        firmware_version = $fwVer
        hardware_model = $hwModel
        hardware_serial = $serial
        health_status = $health
    }
    USB = @{
        vendor_id = $vid
        product_id = $pidVal
        revision = $rev
        serial_number = [string]$serial
        manufacturer_string = if ($disk -and $disk.Manufacturer) { [string]$disk.Manufacturer.Trim() } else { "" }
        product_string = if ($disk -and $disk.Model) { [string]$disk.Model.Trim() } else { $hwModel }
        pnp_device_id = $parentUsbId
        parent_hub_id = $parentHub
        bios_device_path = $biosName
        first_install_time = $firstInstall
    }
    MBRHex = $mbrHex
} | ConvertTo-Json -Compress -Depth 4
`, dl)

	cmd := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	rawOut, err := cmd.Output()
	if err != nil {
		return model.DriveInfo{}, model.USBTopology{}, "", fmt.Errorf("failed to inspect drive %s: %w", targetDrive, err)
	}

	var parsed struct {
		Drive  model.DriveInfo   `json:"Drive"`
		USB    model.USBTopology `json:"USB"`
		MBRHex string            `json:"MBRHex"`
	}
	if err := json.Unmarshal(rawOut, &parsed); err != nil {
		return model.DriveInfo{}, model.USBTopology{}, "", err
	}
	parsed.Drive.ReportedSizeGiB = float64(parsed.Drive.ReportedSizeBytes) / (1024.0 * 1024.0 * 1024.0)
	parsed.Drive.ReportedSizeGB = float64(parsed.Drive.ReportedSizeBytes) / 1e9
	return parsed.Drive, parsed.USB, parsed.MBRHex, nil
}

const (
	ioctlDiskUpdateProperties = 0x00070140
	fsctlDismountVolume       = 0x00090020
)

func sendSCSIRW10(h syscall.Handle, isWrite bool, lba uint32, blocks uint16, dataBuf []byte) bool {
	var pkt scsiPassThroughDirectWithBuffer
	pkt.sptd.Length = uint16(unsafe.Sizeof(pkt.sptd))
	pkt.sptd.CdbLength = 10
	pkt.sptd.SenseInfoLength = 32
	if isWrite {
		pkt.sptd.DataIn = 0 // SCSI_IOCTL_DATA_OUT
		pkt.sptd.Cdb[0] = 0x2A // WRITE(10)
	} else {
		pkt.sptd.DataIn = 1 // SCSI_IOCTL_DATA_IN
		pkt.sptd.Cdb[0] = 0x28 // READ(10)
	}
	pkt.sptd.DataTransferLength = uint32(len(dataBuf))
	pkt.sptd.TimeOutValue = 10
	pkt.sptd.DataBuffer = uintptr(unsafe.Pointer(&dataBuf[0]))
	pkt.sptd.SenseInfoOffset = uint32(unsafe.Offsetof(pkt.SenseBuf))
	binary.BigEndian.PutUint32(pkt.sptd.Cdb[2:6], lba)
	binary.BigEndian.PutUint16(pkt.sptd.Cdb[7:9], blocks)

	var returned uint32
	r1, _, _ := procDeviceIoControl.Call(
		uintptr(h),
		uintptr(ioctlScsiPassThroughDir),
		uintptr(unsafe.Pointer(&pkt)),
		uintptr(unsafe.Sizeof(pkt)),
		uintptr(unsafe.Pointer(&pkt)),
		uintptr(unsafe.Sizeof(pkt)),
		uintptr(unsafe.Pointer(&returned)),
		0,
	)
	return r1 != 0 && pkt.sptd.ScsiStatus == 0
}

// ExecuteLiveHardwareClamp repartitions physical LBA 0 (MBR) via direct SCSI WRITE(10) pass-through
// to clamp Partition #1 to safeBytes, updates OS partition properties, and formats the clamped volume as exFAT.
func ExecuteLiveHardwareClamp(drv model.DriveInfo, safeBytes uint64, label string) error {
	if drv.IsSystemBoot {
		return fmt.Errorf("refusing to clamp system boot drive %s", drv.DevicePath)
	}
	rawPath := drv.RawVolumePath
	if rawPath == "" {
		rawPath = `\\.\` + strings.TrimSuffix(drv.DevicePath, `\`)
	}
	pathPtr, err := syscall.UTF16PtrFromString(rawPath)
	if err != nil {
		return err
	}
	r1, _, e1 := procCreateFileW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(genericRead|genericWrite),
		uintptr(fileShareRead|fileShareWrite),
		0,
		uintptr(openExisting),
		0,
		0,
	)
	h := syscall.Handle(r1)
	if h == syscall.InvalidHandle {
		return fmt.Errorf("failed opening %s for SCSI MBR clamp: %v", rawPath, e1)
	}

	safeSectors := uint32(safeBytes / 512)
	mbr := make([]byte, 512)
	_ = sendSCSIRW10(h, false, 0, 1, mbr)

	// Clear 64-byte partition table at 446..509
	for i := 446; i < 510; i++ {
		mbr[i] = 0
	}
	// Disk signature
	mbr[440], mbr[441], mbr[442], mbr[443] = 0x46, 0x54, 0x33, 0x32
	// Partition #1 entry at 446 (StartLBA = 2048 standard 1MiB alignment, Type = 0x07 exFAT, Length = safeSectors)
	mbr[446+0] = 0x80
	mbr[446+1], mbr[446+2], mbr[446+3] = 0x20, 0x21, 0x00
	mbr[446+4] = 0x07
	mbr[446+5], mbr[446+6], mbr[446+7] = 0xFE, 0xFF, 0xFF
	binary.LittleEndian.PutUint32(mbr[446+8:446+12], 2048)
	binary.LittleEndian.PutUint32(mbr[446+12:446+16], safeSectors)
	mbr[510], mbr[511] = 0x55, 0xAA

	if !sendSCSIRW10(h, true, 0, 1, mbr) {
		syscall.CloseHandle(h)
		return fmt.Errorf("SCSI WRITE(10) to LBA 0 failed on %s", rawPath)
	}

	var bytesRet uint32
	procDeviceIoControl.Call(uintptr(h), uintptr(ioctlDiskUpdateProperties), 0, 0, 0, 0, uintptr(unsafe.Pointer(&bytesRet)), 0)
	procDeviceIoControl.Call(uintptr(h), uintptr(fsctlDismountVolume), 0, 0, 0, 0, uintptr(unsafe.Pointer(&bytesRet)), 0)
	syscall.CloseHandle(h)

	dl := strings.TrimSuffix(strings.TrimPrefix(drv.DevicePath, `\\.\`), `:`)
	if label == "" {
		label = "FLASH_SAFE"
	}
	psFmt := fmt.Sprintf("Start-Sleep -Milliseconds 800; Format-Volume -DriveLetter '%s' -FileSystem exFAT -NewFileSystemLabel '%s' -Confirm:$false | Out-Null", dl, label)
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psFmt)
	return cmd.Run()
}
