package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/flashtruth/flashtruth/internal/attest"
	"github.com/flashtruth/flashtruth/internal/db"
	"github.com/flashtruth/flashtruth/internal/forensics"
	"github.com/flashtruth/flashtruth/internal/hal"
	"github.com/flashtruth/flashtruth/internal/model"
	"github.com/flashtruth/flashtruth/internal/probe"
	"github.com/flashtruth/flashtruth/internal/repair"
)

// RunFullAudit executes the complete 5-layer hardware, forensic, speed, and binary-search capacity audit.
func RunFullAudit(targetDrive string, speedTestMB int, onProgress func(string, int)) (*model.AuditReport, error) {
	notify := func(msg string, pct int) {
		if onProgress != nil {
			onProgress(msg, pct)
		}
	}

	notify("Layer 1/5: Inspecting USB Bus Topology & Physical Drive Geometry...", 5)
	drv, usb, mbrHex, err := hal.InspectDriveHardware(targetDrive)
	if err != nil {
		return nil, err
	}

	notify("Layer 2/5: Sending Raw SCSI Pass-Through CDBs & Resolving OEM Origin...", 15)
	scsi := hal.QuerySCSI(drv.RawVolumePath)
	hal.AnalyzeUSB3Mismatch(&usb, &scsi)
	ctrlMatch := db.LookupController(usb.VendorID, usb.ProductID, scsi.VendorID8, scsi.ProductID16)
	db.ResolveStorageOrigin(&drv, usb, ctrlMatch)

	var bootFor model.BootSectorForensics
	var secScan model.MalwareScanResult
	var speedRes model.SpeedBenchmark
	var capRes model.CapacityVerifyResult

	if drv.IsSystemBoot {
		notify("Layer 3-5: System Boot Drive Detected — Running Safe Read-Only Telemetry Mode...", 80)
		secScan.IsClean = true
		capRes = model.CapacityVerifyResult{
			Tested:                  false,
			NonDestructivePreserved: true,
			IsFakeCapacity:          false,
			FailureMode:             "NONE (SYSTEM_BOOT_PROTECTED)",
			TrueCapacityBytes:       drv.ReportedSizeBytes,
			TrueCapacityGiB:         drv.ReportedSizeGiB,
			TrueCapacityGB:          drv.ReportedSizeGB,
			TrueValidSectors512:     drv.TotalSectors,
		}
	} else {
		notify("Layer 3/5: Analyzing Raw MBR, VBR, Root Directory & Hidden/Malware Artifacts...", 25)
		bootFor = forensics.InspectBootAndRoot(drv, mbrHex)
		secScan = forensics.ScanDriveForMalware(drv.DevicePath)

		notify("Layer 4/5: Running True DMA Unbuffered Hardware Speed Benchmark...", 35)
		speedRes = probe.RunUnbufferedSpeedTest(drv, speedTestMB, func(subMsg string, subPct int) {
			notify("Layer 4/5: "+subMsg, 35+(subPct*20)/100)
		})

		notify("Layer 5/5: Running Non-Destructive LBA Grid Sweep & 4KB Binary Search...", 55)
		capRes = probe.VerifyTrueCapacity(drv, func(subMsg string, subPct int) {
			notify("Layer 5/5: "+subMsg, 55+(subPct*42)/100)
		})
	}

	repairPlan := repair.BuildSafeRepairPlan(drv, capRes)

	rep := &model.AuditReport{
		GeneratedAt:     time.Now().UTC(),
		HostOS:          runtime.GOOS,
		HostArch:        runtime.GOARCH,
		Drive:           drv,
		USB:             usb,
		SCSI:            scsi,
		ControllerMatch: ctrlMatch,
		BootForensics:   bootFor,
		SecurityScan:    secScan,
		SpeedMetrics:    speedRes,
		CapacityProbe:   capRes,
		RepairPlan:      repairPlan,
	}
	rep.Trust = probe.EvaluateTrustScore(rep)

	rawBytes, _ := json.Marshal(rep.CapacityProbe)
	sum := sha256.Sum256(rawBytes)
	rep.ReportID = "FT-" + strings.ToUpper(hex.EncodeToString(sum[:6]))

	att := attest.SignAuditReport(rep, []byte(rep.ReportID))
	rep.AttestationHash = att.CanonicalHash
	rep.AttestationPublicKey = att.PublicKeyHex
	rep.AttestationSignature = att.SignatureHex

	notify("Audit Complete", 100)
	return rep, nil
}

// SaveJSON writes the report as formatted JSON to disk.
func SaveJSON(r *model.AuditReport, path string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

// RenderCertificateHTML generates a standalone Swiss-Grid Hardware Forensics Certificate strictly in the requested language (default "en") with zero language mixing.
func RenderCertificateHTML(r *model.AuditReport, lang ...string) string {
	selectedLang := "en"
	if len(lang) > 0 && strings.ToLower(strings.TrimSpace(lang[0])) == "ar" {
		selectedLang = "ar"
	}

	accent := "#10b981"
	statusBg := "#ecfdf5"
	statusText := "#065f46"
	if !r.Trust.IsAuthentic {
		accent = "#e11d48"
		statusBg = "#fff1f2"
		statusText = "#9f1239"
	}

	isAR := selectedLang == "ar"
	dir := "ltr"
	align := "left"
	borderSide := "border-left"
	if isAR {
		dir = "rtl"
		align = "right"
		borderSide = "border-right"
	}

	var evidenceRows strings.Builder
	for _, e := range r.Trust.Evidence {
		pillBg := "#f0fdf4"
		pillCol := "#15803d"
		if e.Status == "FAIL" {
			pillBg = "#fff1f2"
			pillCol = "#be123c"
		} else if e.Status == "WARN" {
			pillBg = "#fffbeb"
			pillCol = "#b45309"
		}
		title := e.TitleEN
		detail := e.DetailEN
		if isAR {
			title = e.TitleAR
			detail = e.DetailAR
		}
		evidenceRows.WriteString(fmt.Sprintf(`
		<tr>
			<td><span class="pill" style="background:%s;color:%s;">%s (%d)</span></td>
			<td><div class="finding-title">%s</div></td>
			<td><div class="finding-desc">%s</div></td>
			<td><code class="proof">%s</code></td>
		</tr>`, pillBg, pillCol, e.Status, e.Impact, title, detail, e.RawProof))
	}

	docTitle := "Storage Media Authenticity & LBA Verification Certificate"
	secHeader := "Forensic & Hardware Telemetry Evidence"
	lblReported := "Reported OS Capacity"
	lblTrue := "Verified Physical NAND"
	lblPhantom := "Phantom / Spoofed Ratio"
	lblHw := "Hardware Identity & DMA"
	thStatus := "Status"
	thVector := "Check Vector"
	thAnalysis := "Technical Determination"
	thProof := "Raw Hardware Proof"
	verdictText := r.Trust.VerdictEN

	if isAR {
		docTitle = "شهادة الفحص الجنائي والتحقق العتادي من سعة القرص"
		secHeader = "الأدلة الجنائية والقياسات العتادية المباشرة"
		lblReported = "السعة المعلنة للنظام"
		lblTrue = "سعة الـ NAND الفيزيائية الحقيقية"
		lblPhantom = "نسبة السعة الوهمية المزيفة"
		lblHw = "هوية العتاد وسرعة النقل"
		thStatus = "الحالة"
		thVector = "محور الفحص"
		thAnalysis = "التحليل الفني"
		thProof = "الدليل العتادي الخام"
		verdictText = r.Trust.VerdictAR
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="%s" dir="%s">
<head>
<meta charset="UTF-8">
<title>FlashTruth Hardware Forensics Certificate — %s</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  * { box-sizing: border-box; }
  body {
    font-family: 'Plus Jakarta Sans', 'IBM Plex Sans Arabic', -apple-system, BlinkMacSystemFont, sans-serif;
    background: #f4f4f5; color: #09090b; margin: 0; padding: 40px 24px;
    -webkit-font-smoothing: antialiased;
  }
  .sheet {
    max-width: 1080px; margin: 0 auto; background: #ffffff;
    border: 1px solid #d4d4d8; padding: 44px;
    box-shadow: 0 12px 32px rgba(0,0,0,0.06);
  }
  .topbar {
    display: flex; justify-content: space-between; align-items: flex-start;
    border-bottom: 2px solid #09090b; padding-bottom: 24px; margin-bottom: 28px;
  }
  .brand-label { font-family: 'JetBrains Mono', monospace; font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase; color: #71717a; margin-bottom: 6px; }
  h1 { margin: 0; font-size: 24px; font-weight: 800; letter-spacing: -0.02em; }
  .meta { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #52525b; margin-top: 8px; direction: ltr; }
  .score-box { text-align: end; }
  .score-num { font-family: 'JetBrains Mono', monospace; font-size: 36px; font-weight: 700; color: %s; line-height: 1; }
  .score-grade { font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 600; color: %s; margin-top: 6px; }
  .verdict-strip {
    background: %s; %s: 4px solid %s; padding: 18px 22px; margin-bottom: 28px;
  }
  .verdict-main { font-size: 15px; font-weight: 700; color: %s; }
  .metrics-grid {
    display: grid; grid-template-columns: repeat(4, 1fr); border: 1px solid #e4e4e7; margin-bottom: 32px;
  }
  .metric-cell { padding: 18px 20px; border-inline-end: 1px solid #e4e4e7; }
  .metric-cell:last-child { border-inline-end: none; }
  .m-label { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: #71717a; margin-bottom: 8px; }
  .m-val { font-family: 'JetBrains Mono', monospace; font-size: 20px; font-weight: 700; color: #09090b; direction: ltr; text-align: %s; }
  .m-sub { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #71717a; margin-top: 4px; direction: ltr; text-align: %s; }
  h2 { font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: #3f3f46; border-bottom: 1px solid #e4e4e7; padding-bottom: 10px; margin-bottom: 14px; }
  table { width: 100%%; border-collapse: collapse; font-size: 13px; }
  th, td { border-bottom: 1px solid #e4e4e7; padding: 12px 10px; text-align: %s; vertical-align: top; }
  th { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: #71717a; background: #fafafa; }
  .pill { font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 600; padding: 3px 8px; border-radius: 4px; display: inline-block; white-space: nowrap; direction: ltr; }
  .finding-title { font-weight: 700; color: #09090b; }
  .finding-desc { color: #27272a; line-height: 1.55; }
  code.proof { font-family: 'JetBrains Mono', monospace; font-size: 11px; background: #f4f4f5; border: 1px solid #e4e4e7; padding: 4px 6px; display: block; word-break: break-all; color: #18181b; direction: ltr; text-align: left; }
  @media print { body { background: #fff; padding: 0; } .sheet { box-shadow: none; border: none; padding: 20px; } }
</style>
</head>
<body>
<div class="sheet">
  <div class="topbar">
    <div>
      <div class="brand-label">FLASHTRUTH // HARDWARE FORENSICS &amp; NAND CAPACITY VERIFICATION LAB</div>
      <h1>%s</h1>
      <div class="meta">REPORT ID: %s &nbsp;|&nbsp; TIMESTAMP: %s &nbsp;|&nbsp; HOST: %s/%s &nbsp;|&nbsp; TARGET: %s</div>
    </div>
    <div class="score-box">
      <div class="score-num">%d/100</div>
      <div class="score-grade">%s</div>
    </div>
  </div>

  <div class="verdict-strip">
    <div class="verdict-main">%s</div>
  </div>

  <div class="metrics-grid">
    <div class="metric-cell">
      <div class="m-label">%s</div>
      <div class="m-val">%.2f GiB</div>
      <div class="m-sub">%.2f GB (%d B)</div>
    </div>
    <div class="metric-cell">
      <div class="m-label">%s</div>
      <div class="m-val" style="color:%s;">%.3f GiB</div>
      <div class="m-sub">%.2f GB (%d B)</div>
    </div>
    <div class="metric-cell">
      <div class="m-label">%s</div>
      <div class="m-val" style="color:%s;">%.2f%%</div>
      <div class="m-sub">Page: 0x%X</div>
    </div>
    <div class="metric-cell">
      <div class="m-label">%s</div>
      <div class="m-val">%s:%s</div>
      <div class="m-sub">W: %.2f MB/s | R: %.2f MB/s</div>
    </div>
  </div>

  <h2>%s</h2>
  <table>
    <thead>
      <tr>
        <th style="width:110px;">%s</th>
        <th style="width:230px;">%s</th>
        <th>%s</th>
        <th style="width:280px;">%s</th>
      </tr>
    </thead>
    <tbody>
      %s
    </tbody>
  </table>
</div>
</body>
</html>`,
		selectedLang, dir, r.ReportID,
		accent, accent, statusBg, borderSide, accent, statusText,
		align, align, align,
		docTitle,
		r.ReportID, r.GeneratedAt.Format(time.RFC3339), r.HostOS, r.HostArch, r.Drive.DevicePath,
		r.Trust.Score, r.Trust.Grade,
		verdictText,
		lblReported, r.Drive.ReportedSizeGiB, r.Drive.ReportedSizeGB, r.Drive.ReportedSizeBytes,
		lblTrue, accent, r.CapacityProbe.TrueCapacityGiB, r.CapacityProbe.TrueCapacityGB, r.CapacityProbe.TrueCapacityBytes,
		lblPhantom, accent, r.CapacityProbe.FakePercentage, r.CapacityProbe.FirstInvalid4KPage,
		lblHw, r.USB.VendorID, r.USB.ProductID, r.SpeedMetrics.WriteSpeedMBps, r.SpeedMetrics.ReadSpeedMBps,
		secHeader, thStatus, thVector, thAnalysis, thProof,
		evidenceRows.String(),
	)
}
