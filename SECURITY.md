# Security & Hardware Safety Policy

## Non-Destructive Hardware Probing Guarantees

FlashTruth interacts directly with raw block devices (`\\.\X:` on Windows, `/dev/sdX` on Linux, `/dev/rdiskX` on macOS). To ensure zero accidental data loss or kernel instability on user machines:

1. **System Boot Drive Protection (`IsSystemBoot`):** FlashTruth automatically detects the host OS boot/system disk (e.g. `C:`) and enforces read-only hardware/OEM telemetry mode, refusing to lock or write-probe the active operating system partition.
2. **Intel RST VMD Kernel Driver Crash Guard (`iaStorVD.sys` / `BugCheck 0x00000139`):**
   - **Advisory:** Intel Rapid Storage Technology VMD controllers (`PCI\VEN_8086&DEV_A77F`, driver `iaStorVD.sys` v20.x on Windows 11) contain a ring-0 kernel vulnerability where sending raw `IOCTL_STORAGE_QUERY_PROPERTY` (`0x002D1400`) with `PropertyId = 49` (`StorageAdapterProtocolSpecificProperty`) or `PropertyId = 50` (`StorageDeviceProtocolSpecificProperty` NVMe pass-through) corrupts an internal kernel balanced tree (`FAST_FAIL_INVALID_BALANCED_TREE` `0x1d`) and triggers a system BSOD (`BugCheck 0x00000139: KERNEL_SECURITY_CHECK_FAILURE`).
   - **Mitigation in FlashTruth:** FlashTruth strictly prohibits sending `PropertyId 49/50` protocol-specific pass-through IOCTLs to Intel VMD buses (`\_SB.PC00.VMD*` / `VEN_8086&DEV_A77F`), resolving NVMe OEM, IEEE OUI (`EUI-64`), and controller identity safely through user-space PnP/Storage APIs instead.
3. **`+256 MiB` Safe Anchor Offset:** Active capacity probing starts at `+256 MiB` inside the volume rather than `LBA 0`, ensuring that even if a counterfeit controller exhibits modulo LBA address wrap-around, it wraps onto the `+256 MiB` canary page rather than overwriting the MBR, GPT, VBR, FAT, or Root Directory.
4. **`K=0` Canary Monitoring:** Before and after every high-offset probe, FlashTruth re-reads the `K=0` anchor page. If a modulo wrap-around is detected, probing stops immediately and restores the anchor page.
5. **Deterministic Rollback (`defer` Restoration):** Every 4096-byte page probed during the grid sweep and $O(\log N)$ binary search is read into memory prior to modification and restored byte-for-byte before unlocking the volume handle.

## Reporting Security Vulnerabilities

If you discover a security vulnerability or a hardware/driver edge-case that could affect system stability or data integrity, please open a security advisory on GitHub or report it via the repository issue tracker with the `[SECURITY]` prefix.
