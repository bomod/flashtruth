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
- [x] **Live Non-Admin Hardware MBR Clamping (`internal/repair`):** Direct `SCSI WRITE(10)` (`0x2A`) to physical `LBA 0` (`MBR`) + `IOCTL_DISK_UPDATE_PROPERTIES` (`0x00070140`) to clamp counterfeit drives to 97% of verified physical NAND capacity and quarantine phantom LBAs without requiring elevated `diskpart` prompts.
- [x] **Swiss-Industrial Workbench GUI & Dispute Certificate:** Embedded local web dashboard with 6 strictly isolated languages (`EN`, `AR`, `FR`, `ES`, `DE`, `ZH`), `Obsidian`/`Paper` themes, interactive LBA Wafer Map, and printable HTML/JSON Dispute Certificates.

---

## Phase 2: v2.0 — NAND Flash ID (`0x90`) Decoder, HDD CMR/SMR Classifier, SD `CID` Forensics & `Ed25519` Attestation (Completed)

- [x] **Direct NAND Flash Die Read-ID (`ONFI / Toggle 0x90`) Decoder (`internal/db/nand.go`, `--decode-nand`):**
  - Decodes raw 6-to-8 byte **NAND Flash ID (`0x90`)** registers into:
    - **Foundry / Wafer Maker:** `0x2C`/`0xB5` (Micron / Spectek), `0x98` (Kioxia / Toshiba BiCS), `0x45` (SanDisk / Western Digital BiCS), `0xEC` (Samsung V-NAND), `0xAD` (SK Hynix 4D NAND), `0x9B` (YMTC Xtacking), `0x89` (Intel / Solidigm), `0xC8` (GigaDevice), `0xEF` (Winbond), `0xC2` (Macronix).
    - **Cell Architecture & Lithography:** SLC, MLC, 3D TLC, 3D QLC, layer family (`Micron B47R/B58R 176L/232L`, `Kioxia/WD BiCS5 112L`, `Samsung V7/V8`, `YMTC Xtacking 3.0`), and prime OEM vs. downgrade/wafer-sort classification.
- [x] **Mechanical HDD CMR vs. SMR Recording Technology Classifier (`ClassifyHDDRecordingTech` in `internal/db/nand.go`):**
  - Distinguishes **CMR (Conventional Magnetic Recording)** from **SMR (Shingled Magnetic Recording)** across Western Digital (`WD20EZAZ..WD60EZAZ`, `WD20EFAX..WD60EFAX` SMR vs. `EFRX/EFZX/FZBX` CMR), Seagate (`ST2000DM008`, `ST4000DM004`, `ST8000DM004` SMR vs. `IronWolf VN` / `Exos NM` CMR), and Toshiba (`HDWD220/HDWD240/DT02ABA` SMR vs. `HDWD1/MG/X300` CMR), integrated automatically into `ResolveStorageHardwareOrigin`.
- [x] **Hardware SD / microSD 128-bit `CID` Register & `CRC7` Verifier (`internal/forensics/sdcid.go`, `--decode-cid`):**
  - Parses 16-byte (32-hex) raw SD/MMC `CID` registers into `MID` (Manufacturer ID), `OID` (2-char ASCII OEM ID), `PNM` (5-char ASCII Product Name), `PRV` (BCD Hardware Revision), `PSN` (32-bit Serial Number), and `MDT` (Manufacturing Year/Month).
  - Verifies the 7-bit hardware polynomial checksum (`G(x) = x^7 + x^3 + 1`) over the first 15 bytes (`bits [127:8]`) and flags counterfeit/generic bulk SD cards (`MID 0x00/0xFF`, `OID "00"/"??"`).
- [x] **Cryptographically Signed Forensic Audit Certificates (`Ed25519-SHA256`, `internal/attest/signer.go`):**
  - Computes a deterministic `SHA-256` canonical hardware telemetry digest (`AttestationHash`) and signs every JSON/HTML audit report with an `Ed25519` signature (`AttestationSignature`, `AttestationPublicKey`) for tamper-evident e-commerce buyer disputes and enterprise IT asset verification.
- [x] **Kernel Driver Safety Guardrails (`SECURITY.md`):**
  - Documents and enforces strict ring-0 driver safety against the **`Intel RST VMD Controller A77F` (`iaStorVD.sys` v`20.2.13.1038`) `BugCheck 0x00000139 (0x1d)`** kernel crash by prohibiting `IOCTL_STORAGE_QUERY_PROPERTY` (`PropertyId 49/50`) against Intel VMD RAID/NVMe buses.
- [x] **Automated Unit Test Suite & Multi-Arch CI/CD (`.github/workflows/ci.yml`):**
  - Automated unit tests across `internal/attest`, `internal/db`, `internal/forensics`, and `internal/probe` (`go test -v -race ./...`) plus cross-compilation verification across all 6 OS/Arch targets on every push and pull request.

---

## Phase 3: v2.5 — Future Hardware Extensions

- [ ] **SCSI-to-ATA Translation (`SAT`) Bridge Piercing (`CDB 0x85` / `0xA1`):**
  - Tunnel 12-byte and 16-byte ATA Pass-Through CDBs across external USB enclosures (`JMicron JMS578/583`, `ASMedia ASM1153E/2362`, `Realtek RTL9210`) to cross-check internal S.M.A.R.T. Power-On Hours against Seagate FARM (`Log 0xA6`) and ATA GP Device Statistics (`Log 0x04`).
- [ ] **Safe NVMe Admin Queue Passthrough (Non-VMD Standard `stornvme.sys` & Linux `/dev/nvmeXnY`):**
  - Inspect `NVMe Identify Controller (CNS 0x01)` Host Memory Buffer (`HMB`) requests on standard `stornvme.sys` / Linux NVMe controllers (with automatic pre-flight exclusion of `iaStorVD.sys` / Intel VMD controllers).
