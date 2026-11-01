# FlashTruth

**Universal Storage Hardware Forensics, OEM Origin Identifier & Non-Destructive $O(\log N)$ Capacity Verifier**

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](go.mod)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20macOS-blue)](#cross-platform-architecture)
[![Architecture](https://img.shields.io/badge/Arch-amd64%20%7C%20arm64-purple)](#building-from-source)

**FlashTruth** is a zero-dependency, cross-platform hardware forensics engine and desktop/web workbench designed to expose **counterfeit, capacity-spoofed, and relabeled storage media** (USB Flash Drives, External Portable SSDs/HDDs, NVMe PCIe SSDs, SATA SSDs, Mechanical HDDs, and SD/microSD cards) in **~1.2 seconds** instead of hours.

Traditional tools (such as `H2testw`, `F3`, or `ValiDrive`) either take hours to sequentially fill a drive or lack deep controller/SCSI/OEM/boot-sector forensic correlation. **FlashTruth** combines **5 hardware verification layers** into a single self-contained native binary.

---

## Key Capabilities

### 1. 5-Layer Hardware & Forensic Audit Pipeline
| Layer | Module | Technical Mechanism | What It Exposes |
| :--- | :--- | :--- | :--- |
| **Layer 1** | **Bus Topology & OEM Origin** | Queries USB PnP trees, ACPI/BIOS port paths (`DEVPKEY_Device_BiosDeviceName`), PCIe/NVMe descriptors, and IEEE OUI (`EUI-64` / `WWN`) | Exposes fake `"USB 3.0 / 3.2"` drives wired only to USB 2.0 High-Speed (`480 Mbps`, `REV_0200`) pins and identifies true OEM/Fab origin (`Micron`, `Samsung`, `WD/SanDisk`, `Seagate`, `Kioxia`, `SK Hynix`, `Phison`, `SMI`, `JMicron`, `ASMedia`, `Realtek`, `FirstChip`). |
| **Layer 2** | **Raw SCSI / CDB Pass-Through** | Sends raw `SCSI INQUIRY (0x12)` and `SCSI READ CAPACITY(10) (0x25)` via `IOCTL_SCSI_PASS_THROUGH_DIRECT` / `SG_IO` | Matches silicon signatures against known counterfeit factory MPtool templates (`VID_048D&PID_1234` FirstChip `FC1178/FC1179`, Chipsbank `CBM2199`, Micov `MW8209`, Alcor `AU6989`, Norelsys `NS1068X`) and detects synthetic sector counts (`2048 * 1,000,000`). |
| **Layer 3** | **MBR, VBR & Malware Forensics** | Raw sector `0` (MBR `0x1BE`), Partition Start LBA, exFAT/FAT32 VBR, and raw Root Directory (`0xE5` / `0x05`) inspection | Detects non-standard `LBA 32` (`Offset 16384 B`) factory MPtool partitioning, prior deleted files on "brand new" drives, `.lnk` shortcut worms, `autorun.inf`, and NTFS Alternate Data Streams (ADS). |
| **Layer 4** | **True Unbuffered DMA Benchmark** | Page-aligned (`4096 B`) direct DMA transfers (`FILE_FLAG_NO_BUFFERING \| FILE_FLAG_WRITE_THROUGH` / `O_DIRECT` / `F_NOCACHE`) | Measures true physical NAND write/read speed and per-chunk latency without OS RAM caching illusions, grading the underlying NAND (`SLC/pSLC`, `TLC`, `QLC`, or degraded scrap silicon). |
| **Layer 5** | **Non-Destructive $O(\log N)$ Binary Search** | 64-point coarse LBA grid sweep with `K=0` canary monitoring + 20-step 4KB binary search (`+256 MiB` safe anchor) | Pinpoints the **exact last physical 4KB NAND page and 512B sector** in **~1.2 seconds**, distinguishing `BLACK_HOLE_0xFF` (`0xFF` floating bus), `BLACK_HOLE_0x00`, and `LBA_WRAP_AROUND` (modulo address counter overflow) while restoring 100% of original sector bytes. |

---

## Real-World Forensic Case Study (2TB Counterfeit Drive Unmasked in 1.19s)

```text
================================================================================
  FlashTruth v1.0 — Cross-Platform USB Hardware Forensics & Capacity Verifier
  Runtime: windows/amd64 | Direct DMA + SCSI Pass-Through + O(log N) Binary Search
================================================================================
  REPORT ID      : FT-0EA813AE7334
  TRUST SCORE    : 0 / 100  [F (COUNTERFEIT)]
  VERDICT        : COUNTERFEIT DRIVE — Physical NAND is a tiny fraction of claimed capacity!
--------------------------------------------------------------------------------
  [1] STORAGE HARDWARE, OEM & CONTROLLER IDENTITY
      Bus & Media Type   : USB / Removable Flash (Firmware: 2.00, Health: Healthy)
      Hardware Model     : Flash Disk 3.0
      OEM Manufacturer   : Integrated Technology Express, Inc. (ITE)
      Controller / Bridge: FirstChip FC1178BC / FC1179 or Chipsbank CBM2199 (Generic MPtool Template)
      IEEE OUI / VID:PID : USB-IF VID:048D PID:1234 (VID:048D PID:1234 Rev:0200)
      Serial Number      : 9112511085014663328
      BIOS / ACPI Path   : \_SB.PC00.XHCI.RHUB.HS08
      Negotiated Speed   : High-Speed (USB 2.0 — 480 Mbps) (Fake USB 3.0 Claim: true)
      SCSI Inquiry       : 'Flash' / 'Disk 3.0' (Rev '2.00')
      SCSI READ CAPACITY : 0xF423FFFF00000200 (4096000000 sectors)

  [4] PHYSICAL NAND CAPACITY (NON-DESTRUCTIVE BINARY SEARCH IN 1.19s)
      Reported Capacity  :  1953.12 GiB ( 2097.15 GB | 2097152000000 bytes)
      True NAND Capacity :   29.815 GiB (   32.01 GB | 32014008320 bytes)
      Last Valid 4K Page : 0x7742EF (7815919) | Last Valid 512B Sector: 62527359
      First Invalid Page : 0x7742F0 (7815920) | Failure Mode: BLACK_HOLE_0xFF
      Fake Phantom Ratio : 98.47% (2065137991680 bytes fake)
      Data Preserved     : true (100% Non-Destructive Rollback)
```

---

## Industrial Workbench GUI & Multi-Language Support

FlashTruth embeds a zero-dependency **Swiss-Industrial Hardware Workbench GUI** (`internal/server/ui/index.html`) served locally via `--gui`:
- **Strict Single-Language Isolation:** Defaults to pure **English (`EN`)** with full localization across **6 languages** (`EN`, `AR`, `FR`, `ES`, `DE`, `ZH`) and automatic `LTR` / `RTL` layout switching.
- **Dual Precision Themes:** `Obsidian Lab` (dark high-contrast telemetry) and `Cleanroom Paper` (light print/daylight mode).
- **Interactive LBA Wafer Map:** Visualizes every 4KB DMA probe point with live hover inspection of physical LBA, byte offset, written cryptographic tag, hardware readback hex, `K=0` canary integrity, and I/O latency.
- **One-Click Buyer Protection Certificate:** Exports a standalone, print-ready HTML/PDF Forensic Certificate (`--html`) and machine-readable JSON audit log (`--json`) for e-commerce refund disputes.

---

## Quick Start

### 1. Launch Interactive GUI Workbench (Default)
```powershell
# Windows
.\flashtruth-windows-amd64.exe --gui --port 8787

# Linux / macOS
sudo ./flashtruth-linux-amd64 --gui --port 8787
```

### 2. List Connected Storage Volumes (`USB`, `NVMe`, `SATA`, `HDD`, `SD`)
```powershell
.\flashtruth-windows-amd64.exe --list
```

### 3. Run Full 5-Layer CLI Audit & Export Dispute Certificate
```powershell
.\flashtruth-windows-amd64.exe --drive D: --speed-mb 8 --html D_Forensic_Certificate.html --json D_Forensic_Audit.json
```

---

## Building from Source

Requires **Go 1.22+** (tested on **Go 1.26**). Zero CGo or external libraries required.

```powershell
# Build all 6 cross-platform binaries (Windows, Linux, macOS x amd64, arm64) into ./dist/
.\build.ps1
```

Or build directly for your current host:
```bash
go build -trimpath -ldflags="-s -w" -o flashtruth .
```

---

## Cross-Platform Architecture

```text
flashtruth/
├── main.go                          # Unified CLI & Embedded Web Workbench Launcher
├── build.ps1                        # 6-Target Cross-Compiler (Windows/Linux/macOS x amd64/arm64)
├── ROADMAP.md                       # Multi-Phase Universal Storage Forensics Roadmap
└── internal/
    ├── model/types.go               # Hardware Telemetry, SCSI, Forensics & Capacity Schemas
    ├── db/vendors.go                # USB-IF VID/PID, MPtool, Bridge Chip & IEEE OUI Database
    ├── hal/
    │   ├── hal.go                   # Cross-Platform Hardware Abstraction Interface
    │   ├── hal_windows.go           # Win32 CreateFileW NO_BUFFERING, VirtualAlloc & SCSI Pass-Through
    │   ├── hal_linux.go             # Linux O_DIRECT, SG_IO SCSI Pass-Through & sysfs Topology
    │   └── hal_darwin.go            # macOS F_NOCACHE, rdisk Raw I/O & diskutil/system_profiler
    ├── forensics/
    │   ├── bootsector.go            # Raw MBR (0x1BE), LBA-32 Anomaly, exFAT VBR & Root Dir Parser
    │   └── malware.go               # Hidden/System File, Shortcut Worm, Autorun & NTFS ADS Scanner
    ├── probe/
    │   ├── speedtest.go             # Unbuffered Direct DMA Throughput & Latency Profiler
    │   ├── capacity.go              # K=0 Canary Grid Sweep + 4KB O(log N) Binary Search Engine
    │   └── trustscore.go            # Multi-Factor Weighted Authenticity Scoring Engine (0-100)
    ├── repair/repartition.go        # Safe Capacity Lock Generator (PowerShell/diskpart/parted/diskutil)
    ├── report/exporter.go           # Standalone HTML Dispute Certificate & JSON Exporter
    └── server/
        ├── server.go                # Real-Time SSE Telemetry Server
        └── ui/index.html            # Embedded 6-Language Swiss-Industrial Workbench UI
```

---

## Roadmap Summary (Universal Storage Expansion)

See **[ROADMAP.md](ROADMAP.md)** for full technical specifications:
- **Phase 1 (`v1.0` — Current):** USB Flash Drives, External USB Enclosures, Raw SCSI Pass-Through (`0x12`, `0x25`), Unbuffered DMA Speed Test, Non-Destructive $O(\log N)$ Binary Search Capacity Verifier, OEM/OUI Origin Resolution.
- **Phase 2 (`v1.2`):** **Universal HDD & SATA SSD Forensics** via SCSI-to-ATA (`SAT` `0x85`/`0xA1`) USB bridge piercing, `ATA IDENTIFY DEVICE (0xEC)`, **CMR vs. SMR** mechanical platter detection, and **Tampered S.M.A.R.T. Detection** (exposing used HDDs with wiped Power-On Hours via GP Log / Seagate FARM logs).
- **Phase 3 (`v1.5`):** **Native NVMe PCIe Admin Queue Interrogation** (`CNS 0x01`, HMB DRAM-less counterfeit detection for fake flagship NVMe SSDs) + **Direct NAND Flash Die Read-ID (`0x90`)** via vendor-specific CDBs (`Phison`, `SMI`, `Realtek`, `Maxio`, `FirstChip`).
- **Phase 4 (`v2.0`):** **SD / microSD `CID` Hardware Register Forensics** + **Ed25519 Cryptographically Signed Forensic Certificates**.

---

## Contributing & License

Contributions of new counterfeit controller signatures (`VID:PID`, SCSI Inquiry strings, bridge chips, and NVMe/ATA dumps) are welcome! Please see **[CONTRIBUTING.md](CONTRIBUTING.md)** and our **[Counterfeit Drive Issue Template](.github/ISSUE_TEMPLATE/counterfeit_drive_report.yml)**.

Licensed under the **[MIT License](LICENSE)**.
