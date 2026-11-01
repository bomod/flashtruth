# FlashTruth Engineering Roadmap

**Vision:** Build the definitive open-source, cross-platform **Universal Storage Hardware Forensics & Authenticity Verification Engine** covering every storage medium—USB Flash Drives, External Portable SSDs/HDDs, SATA SSDs, Mechanical Hard Drives (HDDs), NVMe M.2 PCIe SSDs, and SD/microSD/CFexpress media—capable of unmasking both **spoofed capacity** and **spoofed manufacturer/controller identity**.

---

## Phase 1: v1.0 — Core Engine, USB/SCSI Pass-Through & Universal Enumeration (Completed)

- [x] **Cross-Platform Single-Binary Engine (`Go 1.26`):** Zero external runtime dependencies across `Windows (amd64/arm64)`, `Linux (amd64/arm64)`, and `macOS (amd64/arm64)`.
- [x] **5-Layer Hardware & Forensic Audit Pipeline:**
  - **Layer 1 (Topology & OEM Origin):** Enumerates USB, NVMe, SATA SSD, and HDD devices; extracts ACPI/BIOS paths (`DEVPKEY_Device_BiosDeviceName`), USB negotiated speed vs. marketing name claims, IEEE OUI from EUI-64/WWN serials, and OEM manufacturer identity.
  - **Layer 2 (Raw SCSI Pass-Through):** Sends `SCSI INQUIRY (0x12)` and `SCSI READ CAPACITY(10) (0x25)` via `IOCTL_SCSI_PASS_THROUGH_DIRECT` / `SG_IO` to detect synthetic MPtool sector formulas and match against known counterfeit controller templates (`FirstChip FC1178/FC1179`, `Chipsbank CBM2199`, `Micov MW8209`, `Alcor AU6989`, `Norelsys NS1068X`).
  - **Layer 3 (Boot Sector & Malware Forensics):** Raw MBR (`0x1BE` partition table), LBA-32 factory MPtool alignment detection, exFAT/FAT32 VBR parsing, raw Root Directory deleted-entry inspection (`0xE5` / `0x05`), and worm/shortcut/ADS scanning.
  - **Layer 4 (True Unbuffered DMA Benchmark):** Page-aligned (`4096 B`) direct hardware read/write speed benchmarking bypassing OS page cache (`FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH` / `O_DIRECT` / `F_NOCACHE`).
  - **Layer 5 (Non-Destructive $O(\log N)$ Binary Search Capacity Verifier):** Coarse grid sweep with `K=0` canary monitoring (to stop immediately on modulo LBA wrap-around before touching filesystem metadata) followed by 20-step 4KB binary search to pinpoint the exact last physical NAND sector in ~1.2 seconds with 100% original data restoration.
- [x] **Safe Capacity Lock (Remediation Generator):** Generates ready-to-run `PowerShell`, `diskpart`, `parted`, and `diskutil` commands to clamp partitions 3% below the true physical NAND boundary and quarantine phantom LBA regions.
- [x] **Swiss-Industrial Workbench GUI & Dispute Certificate:** Embedded local web dashboard with 6 strictly isolated languages (`EN`, `AR`, `FR`, `ES`, `DE`, `ZH`), `Obsidian`/`Paper` themes, interactive LBA Wafer Map, and printable HTML/JSON Dispute Certificates.

---

## Phase 2: v1.2 — Universal HDD / SATA SSD & USB Bridge Piercing (SAT Passthrough)

Many counterfeit "2TB / 4TB / 16TB Portable External SSDs" sold online use a USB-to-SATA bridge chip (`JMicron`, `ASMedia`, `Realtek`, or `Norelsys`) hiding either a tiny microSD card or a relabeled, worn-out mechanical HDD/SSD inside. Furthermore, second-hand enterprise/consumer HDDs frequently have their standard S.M.A.R.T. Power-On Hours wiped to be sold as "Brand New".

- [ ] **SCSI-to-ATA Translation (`SAT`) Bridge Piercing (`CDB 0x85` / `0xA1`):**
  - Tunnel 12-byte and 16-byte ATA Pass-Through CDBs across USB enclosures (`JMicron JMS578/583`, `ASMedia ASM1153E/2362`, `Realtek RTL9210`, `VIA VL716`, `Norelsys NS1068X`) to interrogate the internal SATA device directly behind the USB bridge.
  - Detect **Bridge-to-Drive Mismatches** (e.g., enclosure USB descriptor claims `"Samsung Portable SSD T7"`, while internal ATA `IDENTIFY DEVICE` reports a generic SATA controller or SD-to-SATA converter).
- [ ] **Raw `ATA IDENTIFY DEVICE (0xEC)` Deep Decoder:**
  - Extract true World Wide Name (`WWN` / IEEE OUI words 108–111), nominal form factor, rotation rate (word 217: `0x0001` non-rotating SSD vs. `5400`/`7200`/`10000`/`15000` RPM HDD), TRIM/DRAT/RZAT support, and firmware revision.
- [ ] **Mechanical HDD Platter, CMR vs. SMR & Tampered S.M.A.R.T. Detection:**
  - Distinguish **CMR (Conventional Magnetic Recording)** from **SMR (Shingled Magnetic Recording)** via ATA ACS-4 Zoned Capabilities and model/firmware family lookup (`WD Red`, `Seagate Barracuda`, `Toshiba P300/MG`).
  - Detect **Wiped S.M.A.R.T. Counters (Used HDDs Sold as New):** Cross-check standard `SMART READ DATA (0xB0)` Power-On Hours (Attribute `0x09`) against non-resettable GP Log Pages (`ATA READ LOG EXT 0x2F` Device Statistics Log `0x04` and Seagate **FARM** Log `0xA6` / WD Factory Logs) to expose refurbished drives with cleared S.M.A.R.T. tables.

---

## Phase 3: v1.5 — Native NVMe PCIe Admin Interrogation & Direct NAND Die ID (`0x90`)

Counterfeit internal M.2 NVMe SSDs (e.g., fake `Samsung 980 PRO / 990 PRO` or fake `WD_BLACK SN850X`) flash modified firmware onto budget DRAM-less controllers (`MaxioTech MAP1202/MAP1602`, `Realtek RTS5765DL`, `Innogrit IG5216`) so the OS Device Manager displays the genuine brand name.

- [ ] **Native Cross-Platform NVMe Admin Queue Passthrough:**
  - Windows: `IOCTL_STORAGE_PROTOCOL_COMMAND` (`STORAGE_PROTOCOL_TYPE_NVME`).
  - Linux: `/dev/nvmeXnY` `NVME_IOCTL_ADMIN_CMD` (`0xC0484E41`).
  - macOS: `IONVMeController` user-client telemetry.
- [ ] **NVMe Controller & Silicon Authenticity Verification:**
  - Parse `NVMe Identify Controller (CNS 0x01)` (4096 bytes): verify PCI Vendor ID (`VID`), PCI Subsystem Vendor ID (`SSVID`), IEEE OUI (`[75:73]`), Host Memory Buffer (`HMB`) requests (exposing DRAM-less controllers masquerading as flagship DRAM SSDs!), and Thermal Throttle / Power State descriptors.
  - Detect fake flagship NVMe drives when a drive claiming `"Samsung 990 PRO"` requests HMB (Host Memory Buffer, used only by DRAM-less controllers like Maxio MAP1602) or exposes a Maxio/Realtek Vendor Specific log page.
- [ ] **Direct NAND Flash Die Read-ID (`ONFI / Toggle 0x90`) via Vendor CDBs:**
  - Implement read-only vendor-specific diagnostic commands for major USB/SATA/NVMe controllers (`Phison`, `Silicon Motion SMI`, `Realtek`, `MaxioTech`, `JMicron`, `FirstChip`, `Chipsbank`, `Alcor`) to read the raw 6-to-8 byte **NAND Flash ID (`0x90`)** directly from each chip enable (`CE0..CE7`).
  - Decode the raw NAND ID bytes into:
    - **Foundry / Wafer Maker:** `0x2C`/`0xB5` (Micron), `0x98`/`0x45` (Kioxia / SanDisk BiCS), `0xEC` (Samsung V-NAND), `0xAD` (SK Hynix 4D NAND), `0x9B` (YMTC Xtacking), `0x89` (Intel / Solidigm).
    - **Cell Architecture & Lithography:** SLC, MLC, 3D TLC, 3D QLC, layer count (e.g., 128L, 176L, 232L), die density per CE, and whether the NAND is prime OEM grade or downgraded/scrap ink-die.

---

## Phase 4: v2.0 — SD / microSD / CFexpress Register Forensics & Signed Attestation

- [ ] **Hardware SD / microSD `CID` & `CSD` Register Inspection:**
  - Read the 128-bit `CID` (Card Identification) register on native PCIe/SDHC card readers (`/sys/block/mmcblk*/device/cid` on Linux and `IOCTL_SFFDISK_DEVICE_COMMAND` on Windows) to decode the immutable factory `MID` (Manufacturer ID), `OID` (OEM/Application ID), `PNM` (Product Name), `PRV` (Hardware Revision), and `MDT` (Manufacturing Date), exposing fake "1TB/2TB SanDisk Extreme/Samsung EVO" microSD cards whose `MID/OID` belongs to generic bulk factories.
- [ ] **Cryptographically Verifiable Forensic Certificates (`Ed25519`):**
  - Sign exported JSON/HTML hardware audit reports with deterministic hardware telemetry hashes and optional offline/online verification QR codes for e-commerce buyer disputes and enterprise IT asset receiving.
- [ ] **Community Crowd-Sourced Controller & NAND Signature Registry:**
  - Automated GitHub PR validation pipeline allowing researchers worldwide to contribute verified counterfeit and authentic controller fingerprints into `internal/db/vendors.go`.
