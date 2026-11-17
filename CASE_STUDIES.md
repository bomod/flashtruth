# Empirical Hardware Forensics Case Studies: How Counterfeit Storage Manufacturers Deceive Consumers

**Published by the [FlashTruth](https://github.com/bomod/flashtruth) Hardware Forensics Project**  
**Raw Forensic Datasets:**
- [`docs/case-studies/case-01-2tb-usb3-flash-drive.json`](docs/case-studies/case-01-2tb-usb3-flash-drive.json) (`Report ID: FT-0EA813AE7334`)
- [`docs/case-studies/case-02-500gb-external-ssd.json`](docs/case-studies/case-02-500gb-external-ssd.json) (`Report ID: FT-6251FDAB06FD`)

---

## 1. Executive Summary (ملخص تنفيذي)

Counterfeit storage devices sold across global e-commerce marketplaces no longer rely on simple software tricks—they reprogram the internal **microcontroller firmware (`MPtool`)** of low-cost USB flash chips so that the operating system kernel (`Windows Disk Management`, `macOS Disk Utility`, `Linux lsblk`) genuinely believes the device holds `500 GB`, `1 TB`, or `2 TB`.

Using **FlashTruth's 5-Layer Hardware Audit & Non-Destructive $O(\log N)$ Binary Search Engine**, we conducted sub-second physical hardware investigations on two widely sold deceptive storage products:
1. **Case Study #1 (`FT-0EA813AE7334`):** Advertised as a **"2.0 TB USB 3.0 High-Speed Flash Drive" (`Flash Disk 3.0`)** — unmasked in **`1.19s`** as a **`29.815 GiB` (`32.01 GB`) USB 2.0** stick (`98.47%` phantom space).
2. **Case Study #2 (`FT-6251FDAB06FD`):** Advertised as a **"500 GB Portable External Solid State Drive (`SSD`)"** — unmasked in **`0.70s`** as a **`58.495 GiB` (`62.81 GB`) USB 2.0 thumb drive** hidden inside an external SSD enclosure (`88.32%` phantom space).

### Comparative Forensic Matrix

| Forensic Dimension | Case Study #1: "2 TB USB 3.0 Flash Drive" | Case Study #2: "500 GB External Portable SSD" | Genuine Tier-1 External SSD (Reference) |
| :--- | :--- | :--- | :--- |
| **Report ID** | `FT-0EA813AE7334` | `FT-6251FDAB06FD` | — |
| **Marketing Claim** | `2.0 TB` (`2097.15 GB` / `1953.13 GiB`) USB 3.0 | `500 GB` (`537.92 GB` / `500.98 GiB`) External SSD | `500 GB` / `1 TB` USB 3.2 Gen 2 NVMe/SATA SSD |
| **True Physical NAND** | **`29.815 GiB` (`32.01 GB`)** *(32 GB nominal die)* | **`58.495 GiB` (`62.81 GB`)** *(64 GB nominal die)* | `100%` of advertised LBA count |
| **Phantom Void Ratio** | **`98.47%` Fake** (`2,065,137,991,680` bytes void) | **`88.32%` Fake** (`475,110,801,408` bytes void) | `0.00%` |
| **Last Valid 4KB Page** | `0x7742EF` (`Page 7,815,919` / `Sector 62,527,359`) | `0xE9FAFF` (`Page 15,334,143` / `Sector 122,673,151`) | Matches reported capacity |
| **First Invalid 4KB Page** | `0x7742F0` (`BLACK_HOLE_0xFF`) | `0xE9FB00` (`BLACK_HOLE_0xFF`) | None |
| **USB `VID:PID` & Rev** | `048D:1234` (`REV_0200`) | `048D:1234` (`REV_0200`) | Authentic Vendor VID (`04E8`, `1058`, `0781`, `05DC`) |
| **True Silicon Controller** | `FirstChip FC1178BC/FC1179` or `Chipsbank CBM2199` | `FirstChip FC1178BC/FC1179` or `Chipsbank CBM2199` | Native NVMe/SATA Bridge (`ASMedia`, `Realtek`, `Phison`) |
| **SCSI `INQUIRY` String** | `'Flash   '` / `'Disk 3.0        '` (`Rev 2.00`) | `'VendorCo'` / `'ProductCode     '` (`Rev 2.00`) | True Model + Bridge/Drive Identify |
| **Removable Media Bit (`RMB`)** | `0x80` (`Removable Flash = true`) | `0x80` (`Removable Flash = true` — **Not an SSD!**) | `0x00` (`Fixed Disk / SSD`) |
| **Negotiated Bus Path** | `\_SB.PC00.XHCI.RHUB.HS08` (**USB 2.0 High-Speed**) | `\_SB.PC00.XHCI.RHUB.HS08` (**USB 2.0 High-Speed**) | `\_SB.PC00.XHCI.RHUB.SSxx` (**USB 3.x SuperSpeed**) |
| **True DMA Write Speed** | **`0.30 – 2.26 MB/s`** | **`5.18 MB/s`** (`Max Latency: 604.4 ms`) | **`450 – 1,050 MB/s`** |
| **True DMA Read Speed** | **`30.57 MB/s`** | **`23.26 MB/s`** | **`500 – 1,050 MB/s`** |
| **MBR Disk Signature** | **`33B82CFA`** *(Hardcoded MPtool clone!)* | **`33B82CFA`** *(Hardcoded MPtool clone!)* | Cryptographically random per OS format |
| **exFAT Volume Serial** | **`76E8CACF`** *(Hardcoded MPtool clone!)* | **`76E8CACF`** *(Hardcoded MPtool clone!)* | Random timestamp-derived VSN |
| **Audit Duration** | **`1.19 seconds`** | **`0.70 seconds`** | `~1.0 second` |
| **FlashTruth Verdict** | **`0 / 100 [F // COUNTERFEIT]`** | **`0 / 100 [F // COUNTERFEIT]`** | **`100 / 100 [A+ // AUTHENTIC]`** |

---

## 2. Smoking-Gun Forensic Discovery: The Identical Factory MPtool Fingerprint (`33B82CFA` / `76E8CACF`)

Although **Device #1** was marketed as a **"2 TB USB 3.0 Flash Drive"** and **Device #2** was marketed in a completely different enclosure as a **"500 GB Portable External SSD"**, low-level sector forensics performed by **FlashTruth** proved that both devices were mass-produced using the **exact same factory capacity-spoofing software (`FirstChip FcMpTool`)**:

1. **Identical USB Hardware Descriptor (`VID_048D&PID_1234`):**
   Both devices steal Vendor ID `0x048D` (registered to *Integrated Technology Express, Inc. / ITE*) with dummy Product ID `0x1234` and USB 2.0 revision `0200`.
2. **Byte-for-Byte Identical MBR Disk Signature (`0x33B82CFA`) and Bootstrap Code:**
   Normally, Windows/Linux/macOS generate a unique random 32-bit MBR Disk Signature at offset `0x1B8` and a unique Volume Serial Number (`VSN`) when formatting a drive. Yet both counterfeit drives share the **exact same hardcoded hex values**:
   - **`mbr_signature_hex`:** `"33B82CFA"`
   - **`mbr_bootstrap_hex`:** `"FA33C08ED0BC007C8BF45007501FFBFCBF0006B90001F2A5EA1D060000BEBE07"`
   - **`volume_serial_number`:** `"76E8CACF"`

```mermaid
flowchart TD
    A["Counterfeit Factory Assembly Line (Shenzhen MPtool Station)"] --> B["FirstChip FcMpTool / Chipsbank UMPTool Firmware Injector"]
    B --> C["Hardcoded Template Applied:<br/>• VID:PID = 048D:1234 (REV_0200)<br/>• MBR Signature = 0x33B82CFA<br/>• exFAT Serial = 0x76E8CACF<br/>• Cluster Size = 128 KB (131072 B)"]
    C --> D["Product Line A: Soldered into USB-A Shell<br/>• 32 GB Scrap NAND Die (29.815 GiB)<br/>• Spoofed LBA Count = 4,096,000,000 (2.0 TB)<br/>• SCSI Name: 'Flash Disk 3.0'"]
    C --> E["Product Line B: Glued inside 'External SSD' Case<br/>• 64 GB Planar NAND Die (58.495 GiB)<br/>• Spoofed LBA Count = 1,050,624,000 (537.9 GB)<br/>• SCSI Name: 'VendorCo ProductCode' (Label: 'SSD')"]
    D --> F["FlashTruth O(log N) Audit:<br/>Exposed in 1.19s (98.47% Fake)"]
    E --> G["FlashTruth O(log N) Audit:<br/>Exposed in 0.70s (88.32% Fake)"]
```

---

## 3. Case Study #2 Deep Dive: The Fake "500 GB External SSD" (`FT-6251FDAB06FD`)

### How the Scam Deceives Buyers
1. **Physical Disguise:** The buyer receives a sleek external SSD casing with a USB-C / USB-A cable. Inside the casing, there is **no SATA or NVMe SSD PCB**—only a tiny USB 2.0 flash drive circuit board hot-glued to the connector (often accompanied by a metal weight plate to mimic the heft of a real SSD).
2. **OS-Level Illusion:** When plugged into Windows Explorer, the volume is pre-labeled **`SSD`** and reports **`500.98 GiB` (`537.92 GB`)** of free `exFAT` space. Small test files (a few gigabytes of photos or videos) copy normally because the first **`58.495 GiB`** is backed by a real 64 GB NAND chip.
3. **Silent Catastrophic Data Loss (`BLACK_HOLE_0xFF`):** Because the exFAT File Allocation Table (FAT) and Directory Bitmap reside at the very beginning of the disk (`LBA 64` – `Root Dir Offset 18,481,152 B`, well inside the real 58.495 GiB NAND), the controller successfully updates filenames and directory entries even after the drive is more than 58.5 GiB full! However, every file payload written past **`4KB Page 0xE9FAFF` (`Sector 122,673,151`)** is silently discarded by the controller; when the user later tries to open their files, the controller returns `0xFFFFFFFFFFFFFFFF` (corrupted unreadability).

### Raw FlashTruth Audit Output (`0.70 seconds`)

```text
--------------------------------------------------------------------------------
  REPORT ID      : FT-6251FDAB06FD
  TRUST SCORE    : 0 / 100  [F // COUNTERFEIT]
  VERDICT        : COUNTERFEIT STORAGE MEDIA — Physical NAND capacity is a fraction of advertised LBA count (High Data Loss Risk)
--------------------------------------------------------------------------------
  [1] STORAGE HARDWARE, OEM & CONTROLLER IDENTITY
      Bus & Media Type   : USB / Removable Flash (Firmware: 2.00, Health: Healthy)
      Hardware Model     : VendorCo ProductCode
      OEM Manufacturer   : Integrated Technology Express, Inc. (ITE)
      Controller / Bridge: FirstChip FC1178BC / FC1179 or Chipsbank CBM2199 (Generic MPtool Template)
      IEEE OUI / VID:PID : USB-IF VID:048D PID:1234 (VID:048D PID:1234 Rev:0200)
      Serial Number      : 7019561143358784069
      BIOS / ACPI Path   : \_SB.PC00.XHCI.RHUB.HS08
      Negotiated Speed   : High-Speed (USB 2.0 - 480 Mbps Max) (Fake USB 3.0 Claim: false)
      SCSI Inquiry       : 'VendorCo' / 'ProductCode' (Rev '2.00')
      SCSI READ CAPACITY : 0x3E9F3FFF00000200 (1050624000 sectors)
      Controller Match   : FirstChip FC1178BC / FC1179 or Chipsbank CBM2199 (Generic MPtool Template) [KNOWN_FAKE_TEMPLATE]

  [2] BOOT SECTOR & MALWARE FORENSICS
      Partition Start    : LBA 64 (Offset 32768 B) | MPtool LBA-32 Anomaly: false
      MBR Partition 1    : 8001010007FEFFFF40000000C03F9F3E
      Filesystem & VBR   : exFAT (OEM: 'EXFAT', Cluster: 131072 B)
      Security Scan      : Clean=true | Suspicious=0 | PriorDeletedInRoot=0

  [3] TRUE HARDWARE UNBUFFERED DMA SPEED
      True Write Speed   : 5.18 MB/s (Avg 1MB Latency: 193.0 ms, Max: 604.4 ms)
      True Read Speed    : 23.26 MB/s (Integrity Verified: true)
      NAND Grade Est.    : LOW: Budget USB 2.0 Planar NAND (< 10 MB/s write speed)

  [4] PHYSICAL NAND CAPACITY (NON-DESTRUCTIVE BINARY SEARCH IN 0.70s)
      Reported Capacity  :   500.98 GiB (  537.92 GB | 537919455232 bytes)
      True NAND Capacity :   58.495 GiB (   62.81 GB | 62808653824 bytes)
      Last Valid 4K Page : 0xE9FAFF (15334143) | Last Valid 512B Sector: 122673151
      First Invalid Page : 0xE9FB00 (15334144) | Failure Mode: BLACK_HOLE_0xFF
      Fake Phantom Ratio : 88.32% (475110801408 bytes fake)
      Data Preserved     : true (100% Non-Destructive Rollback)
```

### Exact 18-Step $O(\log N)$ Binary Search Convergence Trace (`docs/case-studies/case-02-500gb-external-ssd.json`)

After the coarse LBA grid sweep found `VALID` storage at `32 GiB` (`Page 0x810000`) and `FAKE_VOID_FF` at `60 GiB` (`Page 0xF10000`), FlashTruth narrowed the `7,340,032`-page interval down to the **single exact 4KB physical boundary page (`0xE9FAFF` vs. `0xE9FB00`)** in just **18 direct DMA probes**:

| Step | Low 4K Page | High 4K Page | Probed Mid Page | Offset (`GiB`) | Physical Sector (`LBA`) | Hardware Readback (`8B Tag`) | Result |
| :---: | :--- | :--- | :--- | :---: | :---: | :--- | :---: |
| **1** | `0x810000` | `0xF0FFFF` | `0xB8FFFF` | `46.250 GiB` | `96,993,272` | `FD59C3C1A1B7A94E` | `VALID` |
| **2** | `0xB90000` | `0xF0FFFF` | `0xD4FFFF` | `53.250 GiB` | `111,673,336` | `C90A75161B854EE3` | `VALID` |
| **3** | `0xD50000` | `0xF0FFFF` | `0xE2FFFF` | `56.750 GiB` | `119,013,368` | `645E6FE863664728` | `VALID` |
| **4** | `0xE30000` | `0xF0FFFF` | `0xE9FFFF` | `58.500 GiB` | `122,683,384` | `FFFFFFFFFFFFFFFF` | **`VOID_FF`** |
| **5** | `0xE30000` | `0xE9FFFE` | `0xE67FFF` | `57.625 GiB` | `120,848,376` | `E5AC4BB254A810F6` | `VALID` |
| **6** | `0xE68000` | `0xE9FFFE` | `0xE83FFF` | `58.062 GiB` | `121,765,880` | `204008654C9EE905` | `VALID` |
| **7** | `0xE84000` | `0xE9FFFE` | `0xE91FFF` | `58.281 GiB` | `122,224,632` | `B98004427EE3AF5E` | `VALID` |
| **8** | `0xE92000` | `0xE9FFFE` | `0xE98FFF` | `58.391 GiB` | `122,454,008` | `0A7459CCBE06AA56` | `VALID` |
| **9** | `0xE99000` | `0xE9FFFE` | `0xE9C7FF` | `58.445 GiB` | `122,568,696` | `9D2C8AA00B3D0DD3` | `VALID` |
| **10** | `0xE9C800` | `0xE9FFFE` | `0xE9E3FF` | `58.473 GiB` | `122,626,040` | `BE66DF1FD71535F7` | `VALID` |
| **11** | `0xE9E400` | `0xE9FFFE` | `0xE9F1FF` | `58.486 GiB` | `122,654,712` | `BA22802B643E63A1` | `VALID` |
| **12** | `0xE9F200` | `0xE9FFFE` | `0xE9F8FF` | `58.493 GiB` | `122,669,048` | `C8653DE80E5629E9` | `VALID` |
| **13** | `0xE9F900` | `0xE9FFFE` | `0xE9FC7F` | `58.497 GiB` | `122,676,216` | `FFFFFFFFFFFFFFFF` | **`VOID_FF`** |
| **14** | `0xE9F900` | `0xE9FC7E` | `0xE9FABF` | `58.495 GiB` | `122,672,632` | `E96FB67FBF81C6A1` | `VALID` |
| **15** | `0xE9FAC0` | `0xE9FC7E` | `0xE9FB9F` | `58.496 GiB` | `122,674,424` | `FFFFFFFFFFFFFFFF` | **`VOID_FF`** |
| **16** | `0xE9FAC0` | `0xE9FB9E` | `0xE9FB2F` | `58.495 GiB` | `122,673,528` | `FFFFFFFFFFFFFFFF` | **`VOID_FF`** |
| **17** | `0xE9FAC0` | `0xE9FB2E` | `0xE9FAF7` | `58.495 GiB` | `122,673,080` | `E5F7B438FF2F2EE2` | `VALID` |
| **18** | `0xE9FAF8` | `0xE9FB2E` | `0xE9FB13` | `58.495 GiB` | `122,673,304` | `FFFFFFFFFFFFFFFF` | **`VOID_FF`** |
| **19** | `0xE9FAF8` | `0xE9FB12` | `0xE9FB05` | `58.495 GiB` | `122,673,192` | `FFFFFFFFFFFFFFFF` | **`VOID_FF`** |
| **20** | `0xE9FAF8` | `0xE9FB04` | `0xE9FAFE` | `58.495 GiB` | `122,673,136` | `C8D9EC4D05737CF7` | `VALID` |
| **21** | `0xE9FAFF` | `0xE9FB04` | `0xE9FB01` | `58.495 GiB` | `122,673,160` | `FFFFFFFFFFFFFFFF` | **`VOID_FF`** |
| **22** | `0xE9FAFF` | `0xE9FB00` | `0xE9FAFF` | **`58.4951 GiB`** | **`122,673,144`** | `F0DC2DA426E84F4B` | **`LAST VALID PAGE`** |

---

## 4. Reclaiming Counterfeit Drives via Non-Admin SCSI `LBA 0` Clamping

Instead of throwing away counterfeit drives, **FlashTruth** includes a hardware remediation engine (`internal/repair`) that sends a direct `SCSI WRITE(10)` (`CDB 0x2A`) to physical `LBA 0` (`MBR`) followed by `IOCTL_DISK_UPDATE_PROPERTIES` (`0x00070140`):
1. **Case Study #1 (`D:` — 2 TB Fake -> `28.59 GiB` Safe):** Successfully clamped to `28.59 GiB` (`30,702,305,280` bytes), quarantining `1.92 TB` of phantom LBA space as unallocated, formatted as `FAT32`, and verified by flashing and booting a complete **Linux Mint 22.3 Cinnamon (64-bit)** live OS image with `SHA-256` verification and `85 / 100 [A // REPAIRED & SAFE]` trust rating.
2. **Case Study #2 (`E:` — 500 GB Fake SSD -> `56.73 GiB` Safe):** Can be safely clamped to `56.73 GiB` (`58,096 MB` / `60.91 GB`), quarantining the remaining `444.25 GiB` phantom region.

---

## 5. الملخص باللغة العربية (Arabic Summary of Findings)

تُثبت هاتان التجربتان العمليتان كفاءة محرك **FlashTruth** في كشف أحدث أساليب الغش التجاري في وسائط التخزين خلال أقل من ثانية واحدة:
1. **التجربة الأولى (`FT-0EA813AE7334` — فلاشة تدّعي سعة `2 TB` وواجهة `USB 3.0`):**
   - كشف البرنامج في **`1.19` ثانية** أن السعة الفيزيائية الحقيقية هي **`29.815 GiB` (`32.01 GB`)** فقط وأن **`98.47%`** من السعة وهمية (`BLACK_HOLE_0xFF`)، وأنها تعمل بمتحكم صيني مقلد (`FirstChip FC1178/FC1179` — `VID_048D&PID_1234`) على منفذ `USB 2.0` فقط.
   - نجح البرنامج في إصلاحها عتادياً وعزل المساحة الوهمية وتثبيت نظام `Linux Mint 22.3` القابل للإقلاع عليها بنجاح.
2. **التجربة الثانية (`FT-6251FDAB06FD` — هارد ديسك خارجي يدّعي أنه `500 GB SSD`):**
   - كشف البرنامج في **`0.70` ثانية** أن القرص **ليس SSD على الإطلاق**، بل هو فلاشة `USB 2.0` رخيصة (`Removable Flash`, `VID_048D&PID_1234`, `VendorCo ProductCode`) مخبأة داخل علبة هارد خارجي!
   - السعة الحقيقية لشريحة الفلاش بالداخل هي **`58.495 GiB` (`62.81 GB`)** فقط، بينما **`88.32%`** (`442.49 GiB`) هي مساحة وهمية تبتلع الملفات وتتلفها فور تجاوز حاجز `58.49 GiB`، وسرعة الكتابة الحقيقية لا تتجاوز **`5.18 MB/s`**.
3. **الدليل الجنائي القاطع على وحدة المصدر المصنعي للغش:**
   - أثبت الفحص الجنائي لقطاعات الإقلاع (`MBR` و`VBR`) أن كلاً من "فلاشة الـ 2 تيرابايت" و"هارد الـ 500 جيجابايت SSD" يحملان **نفس البصمة السداسية المبرمجة مصنعياً** (`MBR Signature = 33B82CFA` و`Volume Serial = 76E8CACF` و`VID:PID = 048D:1234`)، مما يثبت أنهما خرجا من نفس أداة التزوير المصنعية (`FirstChip FcMpTool`).
