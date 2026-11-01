# Contributing to FlashTruth

Thank you for helping unmask counterfeit storage hardware and protect users worldwide from data loss.

## How to Submit a Counterfeit or New Controller Signature

1. Run **FlashTruth** against the drive using the CLI or GUI and export the JSON audit report:
   ```bash
   flashtruth --drive D: --json audit_report.json
   ```
2. Open a new issue using the **Counterfeit / Hardware Signature Report** template, or submit a Pull Request adding the signature to [`internal/db/vendors.go`](internal/db/vendors.go).
3. Include:
   - USB `VID:PID` and Revision (or PCIe `VEN:DEV` / `SSVID` / IEEE OUI for NVMe/SATA drives)
   - Raw `SCSI INQUIRY (0x12)` ASCII & Hex (`inquiry_hex`)
   - Raw `SCSI READ CAPACITY (0x25)` Hex (`read_capacity_hex`)
   - Claimed capacity vs. verified physical NAND capacity (`true_capacity_bytes`)
   - Failure mode (`BLACK_HOLE_0xFF`, `BLACK_HOLE_0x00`, or `LBA_WRAP_AROUND`)

## Code Standards

- **Zero External Runtime Dependencies:** Keep the core engine pure Go standard library + native OS syscalls (`syscall`) so static cross-compilation works out of the box across Windows, Linux, and macOS.
- **Non-Destructive Safety First:** Any active sector probe in `internal/probe/` **must** read and preserve original sector contents before writing a verification tag, monitor the `K=0` canary for modulo LBA wrap-around, and restore original bytes inside a `defer` rollback block.
- **Strict Single-Language Isolation in UI:** When adding UI strings to `internal/server/ui/index.html` or `internal/report/exporter.go`, provide translations for all supported locales (`en`, `ar`, `fr`, `es`, `de`, `zh`) and never mix two languages in the same view.
