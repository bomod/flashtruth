package model

import "time"

// AuditReport is the complete cross-platform forensic and hardware verification report for a drive.
type AuditReport struct {
	ReportID        string               `json:"report_id"`
	GeneratedAt     time.Time            `json:"generated_at"`
	HostOS          string               `json:"host_os"`
	HostArch        string               `json:"host_arch"`
	Drive           DriveInfo            `json:"drive"`
	USB             USBTopology          `json:"usb"`
	SCSI            SCSIFingerprint      `json:"scsi"`
	ControllerMatch ControllerSignature  `json:"controller_match"`
	BootForensics   BootSectorForensics  `json:"boot_forensics"`
	SecurityScan    MalwareScanResult    `json:"security_scan"`
	SpeedMetrics    SpeedBenchmark       `json:"speed_metrics"`
	CapacityProbe   CapacityVerifyResult `json:"capacity_probe"`
	RepairPlan      SafeRepairPlan       `json:"repair_plan"`
	Trust           TrustScorecard       `json:"trust"`
}

// DriveInfo holds OS-level logical and physical disk metadata.
type DriveInfo struct {
	DevicePath         string `json:"device_path"`          // e.g. "D:" on Windows, "/dev/sdb" on Linux, "/dev/disk2" on macOS
	RawVolumePath      string `json:"raw_volume_path"`      // e.g. "\\.\D:" or "/dev/sdb1" or "/dev/rdisk2s1"
	PhysicalDiskPath   string `json:"physical_disk_path"`   // e.g. "\\.\PhysicalDrive1" or "/dev/sdb"
	DiskNumber         int    `json:"disk_number"`
	VolumeLabel        string `json:"volume_label"`
	FileSystem         string `json:"file_system"`
	VolumeSerialNumber string `json:"volume_serial_number"`
	ReportedSizeBytes  uint64 `json:"reported_size_bytes"`
	ReportedSizeGiB    float64 `json:"reported_size_gib"`
	ReportedSizeGB     float64 `json:"reported_size_gb"`
	FreeSpaceBytes     uint64 `json:"free_space_bytes"`
	BytesPerSector     uint32 `json:"bytes_per_sector"`
	AllocationUnitSize uint32 `json:"allocation_unit_size"`
	TotalSectors       uint64 `json:"total_sectors"`
	PartitionStyle     string `json:"partition_style"`      // MBR, GPT, RAW
	PartitionOffset    uint64 `json:"partition_offset"`     // Bytes from sector 0
	PartitionStartLBA  uint64  `json:"partition_start_lba"`  // e.g. 32 (MPtool) vs 2048 (Standard OS)
	PartitionActive    bool    `json:"partition_active"`
	IsRemovable        bool    `json:"is_removable"`
	IsSystemBoot       bool    `json:"is_system_boot"`
	BusType            string  `json:"bus_type"`             // USB, NVMe, SATA, SAS, SD, MMC
	MediaType          string  `json:"media_type"`           // SSD, HDD, Removable Flash, SCM
	SpindleSpeed       uint32  `json:"spindle_speed"`        // 0 for SSD/Flash, 5400/7200/10000/15000 for HDD
	FirmwareVersion    string  `json:"firmware_version"`     // Controller firmware revision
	HardwareModel      string  `json:"hardware_model"`       // Raw hardware model string
	HardwareSerial     string  `json:"hardware_serial"`      // Raw controller/drive serial or EUI-64/WWN
	HealthStatus       string  `json:"health_status"`        // Healthy, Warning, Unhealthy
	OEMManufacturer    string  `json:"oem_manufacturer"`     // Resolved true OEM / Fab manufacturer
	ControllerVendor   string  `json:"controller_vendor"`    // Resolved controller or bridge chip developer
	IEEEOUI            string  `json:"ieee_oui"`             // Resolved IEEE OUI from EUI-64/WWN serial
}

// USBTopology holds physical USB bus descriptors and negotiated speed.
type USBTopology struct {
	VendorID            string `json:"vendor_id"`              // e.g. "048D"
	ProductID           string `json:"product_id"`             // e.g. "1234"
	Revision            string `json:"revision"`               // e.g. "0200" (USB 2.0)
	SerialNumber        string `json:"serial_number"`          // e.g. "9112511085014663328"
	ManufacturerString  string `json:"manufacturer_string"`
	ProductString       string `json:"product_string"`
	PNPDeviceID         string `json:"pnp_device_id"`
	ParentHubID         string `json:"parent_hub_id"`
	BIOSDevicePath      string `json:"bios_device_path"`       // e.g. "\_SB.PC00.XHCI.RHUB.HS08"
	NegotiatedSpeed     string `json:"negotiated_speed"`       // "High-Speed (USB 2.0 - 480 Mbps)" vs "SuperSpeed (USB 3.x - 5+ Gbps)"
	ClaimedUSB3InName   bool   `json:"claimed_usb3_in_name"`   // True if name claims "3.0" / "3.1" / "3.2"
	IsFakeUSB3Speed     bool   `json:"is_fake_usb3_speed"`     // True if claims USB 3.x but runs on USB 2.0 HS port/REV_0200
	FirstInstallTime    string `json:"first_install_time"`
}

// SCSIFingerprint holds raw responses from SCSI INQUIRY and READ CAPACITY CDBs.
type SCSIFingerprint struct {
	Supported              bool   `json:"supported"`
	InquiryHex             string `json:"inquiry_hex"`
	InquiryASCII           string `json:"inquiry_ascii"`
	VendorID8              string `json:"vendor_id_8"`
	ProductID16            string `json:"product_id_16"`
	ProductRev4            string `json:"product_rev_4"`
	ReadCapacityHex        string `json:"read_capacity_hex"`
	ReportedLastLBA        uint64 `json:"reported_last_lba"`
	ReportedTotalSectors   uint64 `json:"reported_total_sectors"`
	ReportedSectorSize     uint32 `json:"reported_sector_size"`
	IsSyntheticMPtoolRound bool   `json:"is_synthetic_mptool_round"` // e.g. exact multiple of 2048 * 1000000
	SyntheticFormulaNote   string `json:"synthetic_formula_note"`
}

// ControllerSignature represents the matched entry from the Known USB Controller Database.
type ControllerSignature struct {
	VID                 string `json:"vid"`
	PID                 string `json:"pid"`
	RegisteredOwner     string `json:"registered_owner"`
	ActualController    string `json:"actual_controller"`
	Category            string `json:"category"` // "AUTHENTIC_BRAND", "KNOWN_FAKE_TEMPLATE", "GENERIC_CONTROLLER", "UNKNOWN"
	RiskLevel           string `json:"risk_level"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	CommonMPtools       string `json:"common_mptools"`
	DescriptionAR       string `json:"description_ar"`
	DescriptionEN       string `json:"description_en"`
}

// BootSectorForensics holds raw MBR, VBR, and Root Directory forensic findings.
type BootSectorForensics struct {
	Inspected             bool                  `json:"inspected"`
	MBRSignatureHex       string                `json:"mbr_signature_hex"`
	MBRBootstrapHex       string                `json:"mbr_bootstrap_hex"`
	MBRPartitionEntry1Hex string                `json:"mbr_partition_entry1_hex"`
	IsMPtoolLBA32Layout   bool                  `json:"is_mptool_lba32_layout"`
	VBROEMName            string                `json:"vbr_oem_name"`
	VBRBootJumpHex        string                `json:"vbr_boot_jump_hex"`
	VBRVolumeLengthSectors uint64               `json:"vbr_volume_length_sectors"`
	VBRClusterSize        uint32                `json:"vbr_cluster_size"`
	VBRClusterCount       uint32                `json:"vbr_cluster_count"`
	RootDirOffsetBytes    uint64                `json:"root_dir_offset_bytes"`
	RootDirEntries        []RawDirectoryEntry   `json:"root_dir_entries"`
	PriorDeletedFilesCount int                  `json:"prior_deleted_files_count"`
}

// RawDirectoryEntry represents a 32-byte raw entry in the root directory cluster.
type RawDirectoryEntry struct {
	Offset      int    `json:"offset"`
	EntryType   string `json:"entry_type"`
	InUse       bool   `json:"in_use"`
	Description string `json:"description"`
	DecodedName string `json:"decoded_name,omitempty"`
	RawHex16    string `json:"raw_hex_16"`
}

// MalwareScanResult holds security and hidden file analysis.
type MalwareScanResult struct {
	Scanned             bool                `json:"scanned"`
	TotalFiles          int                 `json:"total_files"`
	HiddenFilesCount    int                 `json:"hidden_files_count"`
	SystemFilesCount    int                 `json:"system_files_count"`
	SuspiciousCount     int                 `json:"suspicious_count"`
	ADSCount            int                 `json:"ads_count"`
	HasAutorunInf       bool                `json:"has_autorun_inf"`
	HasShortcutWorm     bool                `json:"has_shortcut_worm"`
	IsClean             bool                `json:"is_clean"`
	Findings            []SecurityFinding   `json:"findings"`
	AllItems            []FileEntrySummary  `json:"all_items"`
}

type SecurityFinding struct {
	Severity    string `json:"severity"` // "INFO", "WARNING", "CRITICAL"
	Path        string `json:"path"`
	ReasonAR    string `json:"reason_ar"`
	ReasonEN    string `json:"reason_en"`
}

type FileEntrySummary struct {
	Path          string `json:"path"`
	SizeBytes     int64  `json:"size_bytes"`
	Attributes    string `json:"attributes"`
	CreatedUTC    string `json:"created_utc"`
	ModifiedUTC   string `json:"modified_utc"`
	StreamName    string `json:"stream_name,omitempty"`
}

// SpeedBenchmark holds true hardware unbuffered DMA read/write performance metrics.
type SpeedBenchmark struct {
	Tested              bool    `json:"tested"`
	TestSizeMB          int     `json:"test_size_mb"`
	WriteTimeSec        float64 `json:"write_time_sec"`
	WriteSpeedMBps      float64 `json:"write_speed_mbps"`
	ReadTimeSec         float64 `json:"read_time_sec"`
	ReadSpeedMBps       float64 `json:"read_speed_mbps"`
	MinChunkWriteMs     float64 `json:"min_chunk_write_ms"`
	MaxChunkWriteMs     float64 `json:"max_chunk_write_ms"`
	AvgChunkWriteMs     float64 `json:"avg_chunk_write_ms"`
	IntegrityVerified   bool    `json:"integrity_verified"`
	NANDQualityEstimate string  `json:"nand_quality_estimate"`
}

// CapacityVerifyResult holds the results of the Grid Sweep + Binary Search capacity verification.
type CapacityVerifyResult struct {
	Tested                   bool              `json:"tested"`
	NonDestructivePreserved  bool              `json:"non_destructive_preserved"`
	DurationSeconds          float64           `json:"duration_seconds"`
	IsFakeCapacity           bool              `json:"is_fake_capacity"`
	FailureMode              string            `json:"failure_mode"` // "NONE", "BLACK_HOLE_0xFF", "BLACK_HOLE_0x00", "LBA_WRAP_AROUND", "IO_ERROR"
	WrapAroundDetectedAtGiB  float64           `json:"wrap_around_detected_at_gib,omitempty"`
	LastValid4KPage          uint64            `json:"last_valid_4k_page"`
	FirstInvalid4KPage       uint64            `json:"first_invalid_4k_page"`
	TrueValidSectors512      uint64            `json:"true_valid_sectors_512"`
	TrueCapacityBytes        uint64            `json:"true_capacity_bytes"`
	TrueCapacityGiB          float64           `json:"true_capacity_gib"`
	TrueCapacityGB           float64           `json:"true_capacity_gb"`
	FakeCapacityBytes        uint64            `json:"fake_capacity_bytes"`
	FakePercentage           float64           `json:"fake_percentage"`
	GridProbes               []ProbePoint      `json:"grid_probes"`
	BinarySearchSteps        []BinarySearchStep `json:"binary_search_steps"`
}

type ProbePoint struct {
	Index         int     `json:"index"`
	OffsetGiB     float64 `json:"offset_gib"`
	PhysicalByte  uint64  `json:"physical_byte"`
	PhysicalLBA   uint64  `json:"physical_lba"`
	Status        string  `json:"status"` // "VALID", "FAKE_VOID_FF", "FAKE_VOID_00", "WRAP_AROUND", "ERROR"
	WrittenTagHex string  `json:"written_tag_hex"`
	ReadTagHex    string  `json:"read_tag_hex"`
	CanaryIntact  bool    `json:"canary_intact"`
	LatencyMs     float64 `json:"latency_ms"`
}

type BinarySearchStep struct {
	Step         int     `json:"step"`
	LowPage4K    uint64  `json:"low_page_4k"`
	HighPage4K   uint64  `json:"high_page_4k"`
	MidPage4K    uint64  `json:"mid_page_4k"`
	MidOffsetGiB float64 `json:"mid_offset_gib"`
	MidPhysicalLBA uint64 `json:"mid_physical_lba"`
	Valid        bool    `json:"valid"`
	ReadBackHex  string  `json:"read_back_hex"`
}

// SafeRepairPlan holds the calculated safe partition boundary to quarantine fake space.
type SafeRepairPlan struct {
	Needed                bool    `json:"needed"`
	TrueMaxBytes          uint64  `json:"true_max_bytes"`
	RecommendedSafeBytes  uint64  `json:"recommended_safe_bytes"` // 97% of true capacity to leave safety buffer
	RecommendedSafeGiB    float64 `json:"recommended_safe_gib"`
	RecommendedSafeMB     uint64  `json:"recommended_safe_mb"`
	QuarantinedFakeGiB    float64 `json:"quarantined_fake_gib"`
	WindowsDiskpartScript string  `json:"windows_diskpart_script"`
	WindowsPowerShellCmd  string  `json:"windows_powershell_cmd"`
	LinuxPartedCmd        string  `json:"linux_parted_cmd"`
	MacOSDiskutilCmd      string  `json:"macos_diskutil_cmd"`
}

// TrustScorecard summarizes the overall authenticity and safety rating.
type TrustScorecard struct {
	Score       int            `json:"score"`       // 0 - 100
	Grade       string         `json:"grade"`       // A+, A, B, C, D, F (COUNTERFEIT)
	VerdictAR   string         `json:"verdict_ar"`
	VerdictEN   string         `json:"verdict_en"`
	IsAuthentic bool           `json:"is_authentic"`
	Evidence    []EvidenceItem `json:"evidence"`
}

type EvidenceItem struct {
	Category   string `json:"category"`
	Status     string `json:"status"` // "PASS", "WARN", "FAIL"
	Impact     int    `json:"impact"` // Score delta e.g. -60
	TitleAR    string `json:"title_ar"`
	TitleEN    string `json:"title_en"`
	DetailAR   string `json:"detail_ar"`
	DetailEN   string `json:"detail_en"`
	RawProof   string `json:"raw_proof"`
}
