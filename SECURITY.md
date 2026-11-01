# Security & Hardware Safety Policy

## Non-Destructive Hardware Probing Guarantees

FlashTruth interacts directly with raw block devices (`\\.\X:` on Windows, `/dev/sdX` on Linux, `/dev/rdiskX` on macOS). To ensure zero accidental data loss on legitimate user drives:

1. **System Boot Drive Protection (`IsSystemBoot`):** FlashTruth automatically detects the host OS boot/system disk (e.g. `C:`) and enforces read-only hardware/OEM telemetry mode, refusing to lock or write-probe the active operating system partition.
2. **`+256 MiB` Safe Anchor Offset:** Active capacity probing starts at `+256 MiB` inside the volume rather than `LBA 0`, ensuring that even if a counterfeit controller exhibits modulo LBA address wrap-around, it wraps onto the `+256 MiB` canary page rather than overwriting the MBR, GPT, VBR, FAT, or Root Directory.
3. **`K=0` Canary Monitoring:** Before and after every high-offset probe, FlashTruth re-reads the `K=0` anchor page. If a modulo wrap-around is detected, probing stops immediately and restores the anchor page.
4. **Deterministic Rollback (`defer` Restoration):** Every 4096-byte page probed during the grid sweep and $O(\log N)$ binary search is read into memory prior to modification and restored byte-for-byte before unlocking the volume handle.

## Reporting Security Vulnerabilities

If you discover a security vulnerability or a hardware edge-case that could affect data integrity, please open a private security advisory on GitHub or report it via the repository issue tracker with the `[SECURITY]` prefix.
