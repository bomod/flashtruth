package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/flashtruth/flashtruth/internal/hal"
	"github.com/flashtruth/flashtruth/internal/model"
	"github.com/flashtruth/flashtruth/internal/report"
	"github.com/flashtruth/flashtruth/internal/server"
)

func main() {
	listFlag := flag.Bool("list", false, "List connected removable/USB storage drives")
	driveFlag := flag.String("drive", "", "Target drive to audit (e.g. D: on Windows, /dev/sdb on Linux, /dev/disk2 on macOS)")
	speedMBFlag := flag.Int("speed-mb", 8, "Unbuffered hardware DMA benchmark size in MB")
	jsonOutFlag := flag.String("json", "", "Save full forensic audit report to JSON file")
	htmlOutFlag := flag.String("html", "", "Save standalone Forensic Dispute Certificate to HTML file")
	guiFlag := flag.Bool("gui", false, "Launch interactive Web/Desktop Dashboard GUI")
	portFlag := flag.Int("port", 8787, "Port for interactive GUI server")
	noBrowserFlag := flag.Bool("no-browser", false, "Do not auto-open browser when starting --gui")
	flag.Parse()

	printBanner()

	if *listFlag {
		drives, err := hal.ListDrives()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error listing drives: %v\n", err)
			os.Exit(1)
		}
		if len(drives) == 0 {
			fmt.Println("No storage drives detected.")
			return
		}
		fmt.Printf("Detected %d Storage Volume(s) (USB / NVMe / SATA / HDD / SD):\n", len(drives))
		for _, d := range drives {
			fmt.Printf("  - %-4s | Bus: %-5s | Media: %-15s | Model: %-24s | Reported: %8.2f GiB (%8.2f GB) | FW: %s\n",
				d.DevicePath, d.BusType, d.MediaType, d.HardwareModel, d.ReportedSizeGiB, d.ReportedSizeGB, d.FirmwareVersion)
		}
		return
	}

	var initialReport *model.AuditReport
	if *driveFlag != "" {
		fmt.Printf("[*] Starting 5-Layer Hardware & Forensic Audit on %s ...\n", *driveFlag)
		rep, err := report.RunFullAudit(*driveFlag, *speedMBFlag, func(msg string, pct int) {
			fmt.Printf("\r    [%3d%%] %-72s", pct, msg)
		})
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Audit failed: %v\n", err)
			os.Exit(1)
		}
		initialReport = rep
		printCLIReport(rep)

		if *jsonOutFlag != "" {
			if err := report.SaveJSON(rep, *jsonOutFlag); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed saving JSON: %v\n", err)
			} else {
				fmt.Printf("[+] Saved JSON Forensic Report     -> %s\n", *jsonOutFlag)
			}
		}
		if *htmlOutFlag != "" {
			html := report.RenderCertificateHTML(rep)
			if err := os.WriteFile(*htmlOutFlag, []byte(html), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed saving HTML: %v\n", err)
			} else {
				fmt.Printf("[+] Saved HTML Dispute Certificate -> %s\n", *htmlOutFlag)
			}
		}
	}

	if *guiFlag || (*driveFlag == "" && !*listFlag) {
		addr := fmt.Sprintf("127.0.0.1:%d", *portFlag)
		url := "http://" + addr
		fmt.Printf("\n[*] FlashTruth Interactive GUI Dashboard listening on %s\n", url)
		if !*noBrowserFlag {
			openBrowser(url)
		}
		srv := server.NewServer(initialReport)
		if err := http.ListenAndServe(addr, srv.Handler()); err != nil {
			fmt.Fprintf(os.Stderr, "[!] GUI Server error: %v\n", err)
			os.Exit(1)
		}
	}
}

func printBanner() {
	fmt.Println("================================================================================")
	fmt.Println("  FlashTruth v1.0 — Cross-Platform USB Hardware Forensics & Capacity Verifier")
	fmt.Printf("  Runtime: %s/%s | Direct DMA + SCSI Pass-Through + O(log N) Binary Search\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println("================================================================================")
}

func printCLIReport(r *model.AuditReport) {
	fmt.Println("\n--------------------------------------------------------------------------------")
	fmt.Printf("  REPORT ID      : %s\n", r.ReportID)
	fmt.Printf("  TRUST SCORE    : %d / 100  [%s]\n", r.Trust.Score, r.Trust.Grade)
	fmt.Printf("  VERDICT        : %s\n", r.Trust.VerdictEN)
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("  [1] STORAGE HARDWARE, OEM & CONTROLLER IDENTITY\n")
	fmt.Printf("      Bus & Media Type   : %s / %s (Firmware: %s, Health: %s)\n", r.Drive.BusType, r.Drive.MediaType, r.Drive.FirmwareVersion, r.Drive.HealthStatus)
	fmt.Printf("      Hardware Model     : %s\n", r.Drive.HardwareModel)
	fmt.Printf("      OEM Manufacturer   : %s\n", r.Drive.OEMManufacturer)
	fmt.Printf("      Controller / Bridge: %s\n", r.Drive.ControllerVendor)
	fmt.Printf("      IEEE OUI / VID:PID : %s (VID:%s PID:%s Rev:%s)\n", r.Drive.IEEEOUI, r.USB.VendorID, r.USB.ProductID, r.USB.Revision)
	fmt.Printf("      Serial Number      : %s\n", r.USB.SerialNumber)
	fmt.Printf("      BIOS / ACPI Path   : %s\n", r.USB.BIOSDevicePath)
	fmt.Printf("      Negotiated Speed   : %s (Fake USB 3.0 Claim: %v)\n", r.USB.NegotiatedSpeed, r.USB.IsFakeUSB3Speed)
	fmt.Printf("      SCSI Inquiry       : '%s' / '%s' (Rev '%s')\n", r.SCSI.VendorID8, r.SCSI.ProductID16, r.SCSI.ProductRev4)
	fmt.Printf("      SCSI READ CAPACITY : 0x%s (%d sectors)\n", r.SCSI.ReadCapacityHex, r.SCSI.ReportedTotalSectors)
	fmt.Printf("      Controller Match   : %s [%s]\n", r.ControllerMatch.ActualController, r.ControllerMatch.Category)
	fmt.Println()
	fmt.Printf("  [2] BOOT SECTOR & MALWARE FORENSICS\n")
	fmt.Printf("      Partition Start    : LBA %d (Offset %d B) | MPtool LBA-32 Anomaly: %v\n",
		r.Drive.PartitionStartLBA, r.Drive.PartitionOffset, r.BootForensics.IsMPtoolLBA32Layout)
	fmt.Printf("      MBR Partition 1    : %s\n", r.BootForensics.MBRPartitionEntry1Hex)
	fmt.Printf("      Filesystem & VBR   : %s (OEM: '%s', Cluster: %d B)\n",
		r.Drive.FileSystem, strings.TrimSpace(r.BootForensics.VBROEMName), r.BootForensics.VBRClusterSize)
	fmt.Printf("      Security Scan      : Clean=%v | Suspicious=%d | PriorDeletedInRoot=%d\n",
		r.SecurityScan.IsClean, r.SecurityScan.SuspiciousCount, r.BootForensics.PriorDeletedFilesCount)
	fmt.Println()
	fmt.Printf("  [3] TRUE HARDWARE UNBUFFERED DMA SPEED\n")
	fmt.Printf("      True Write Speed   : %.2f MB/s (Avg 1MB Latency: %.1f ms, Max: %.1f ms)\n",
		r.SpeedMetrics.WriteSpeedMBps, r.SpeedMetrics.AvgChunkWriteMs, r.SpeedMetrics.MaxChunkWriteMs)
	fmt.Printf("      True Read Speed    : %.2f MB/s (Integrity Verified: %v)\n",
		r.SpeedMetrics.ReadSpeedMBps, r.SpeedMetrics.IntegrityVerified)
	fmt.Printf("      NAND Grade Est.    : %s\n", r.SpeedMetrics.NANDQualityEstimate)
	fmt.Println()
	fmt.Printf("  [4] PHYSICAL NAND CAPACITY (NON-DESTRUCTIVE BINARY SEARCH IN %.2fs)\n", r.CapacityProbe.DurationSeconds)
	fmt.Printf("      Reported Capacity  : %8.2f GiB (%8.2f GB | %d bytes)\n",
		r.Drive.ReportedSizeGiB, r.Drive.ReportedSizeGB, r.Drive.ReportedSizeBytes)
	fmt.Printf("      True NAND Capacity : %8.3f GiB (%8.2f GB | %d bytes)\n",
		r.CapacityProbe.TrueCapacityGiB, r.CapacityProbe.TrueCapacityGB, r.CapacityProbe.TrueCapacityBytes)
	fmt.Printf("      Last Valid 4K Page : 0x%X (%d) | Last Valid 512B Sector: %d\n",
		r.CapacityProbe.LastValid4KPage, r.CapacityProbe.LastValid4KPage, r.CapacityProbe.TrueValidSectors512-1)
	fmt.Printf("      First Invalid Page : 0x%X (%d) | Failure Mode: %s\n",
		r.CapacityProbe.FirstInvalid4KPage, r.CapacityProbe.FirstInvalid4KPage, r.CapacityProbe.FailureMode)
	fmt.Printf("      Fake Phantom Ratio : %.2f%% (%d bytes fake)\n",
		r.CapacityProbe.FakePercentage, r.CapacityProbe.FakeCapacityBytes)
	fmt.Printf("      Data Preserved     : %v (100%% Non-Destructive Rollback)\n", r.CapacityProbe.NonDestructivePreserved)

	if r.RepairPlan.Needed {
		fmt.Println()
		fmt.Printf("  [5] SAFE CAPACITY LOCK (REPAIR PLAN)\n")
		fmt.Printf("      Recommended Safe Partition : %.2f GiB (%d MB)\n", r.RepairPlan.RecommendedSafeGiB, r.RepairPlan.RecommendedSafeMB)
		fmt.Printf("      Quarantined Fake Space     : %.2f GiB (Unallocated)\n", r.RepairPlan.QuarantinedFakeGiB)
	}
	fmt.Println("--------------------------------------------------------------------------------")
	_ = json.Marshal
}

func openBrowser(url string) {
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		_ = exec.Command("open", url).Start()
	default:
		_ = exec.Command("xdg-open", url).Start()
	}
}
