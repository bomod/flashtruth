package db

import (
	"fmt"
	"strings"

	"github.com/flashtruth/flashtruth/internal/model"
)

type VendorRecord struct {
	VID              string
	PID              string // "*" matches any PID for this VID if no exact PID match
	RegisteredOwner  string
	ActualController string
	Category         string
	RiskLevel        string
	CommonMPtools    string
	DescriptionAR    string
	DescriptionEN    string
}

var knownSignatures = []VendorRecord{
	// === KNOWN FAKE / MPTOOL TEMPLATE SIGNATURES ===
	{
		VID:              "048D",
		PID:              "1234",
		RegisteredOwner:  "Integrated Technology Express, Inc. (ITE)",
		ActualController: "FirstChip FC1178BC / FC1179 or Chipsbank CBM2199 (Generic MPtool Template)",
		Category:         "KNOWN_FAKE_TEMPLATE",
		RiskLevel:        "CRITICAL",
		CommonMPtools:    "FirstChip FcMpTool / Chipsbank UMPTool / APtool",
		DescriptionAR:    "المعرف 048D:1234 هو أشهر قالب افتراضي للمتحكمات الصينية الرخيصة (FirstChip / Chipsbank) المستخدمة في الفلاشات المزورة التي تنتحل سعات 1TB و2TB وأسماء مثل Flash Disk 3.0 أو VendorCo ProductCode.",
		DescriptionEN:    "VID 048D / PID 1234 is the single most notorious default factory template for cheap Chinese controllers (FirstChip FC1178/FC1179 & Chipsbank CBM2199) used in fake-capacity 1TB/2TB flash drives.",
	},
	{
		VID:              "048D",
		PID:              "1178",
		RegisteredOwner:  "Integrated Technology Express, Inc. (ITE) / FirstChip",
		ActualController: "FirstChip FC1178",
		Category:         "KNOWN_FAKE_TEMPLATE",
		RiskLevel:        "HIGH",
		CommonMPtools:    "FirstChip FcMpTool",
		DescriptionAR:    "متحكم FirstChip FC1178 صيني منخفض التكلفة، يُستخدم بكثرة في الفلاشات بدون علامة تجارية والفلاشات المعدلة برمجياً لتضخيم السعة.",
		DescriptionEN:    "FirstChip FC1178 budget controller frequently used in white-label and capacity-spoofed USB flash drives.",
	},
	{
		VID:              "048D",
		PID:              "1179",
		RegisteredOwner:  "Integrated Technology Express, Inc. (ITE) / FirstChip",
		ActualController: "FirstChip FC1179",
		Category:         "KNOWN_FAKE_TEMPLATE",
		RiskLevel:        "HIGH",
		CommonMPtools:    "FirstChip FcMpTool",
		DescriptionAR:    "متحكم FirstChip FC1179 صيني منخفض التكلفة، شائع جداً في الفلاشات المقلدة ذات السعات الوهمية.",
		DescriptionEN:    "FirstChip FC1179 budget controller widely used in counterfeit high-capacity USB drives.",
	},
	{
		VID:              "FFFF",
		PID:              "5678",
		RegisteredOwner:  "Unassigned / Invalid USB-IF VID (0xFFFF)",
		ActualController: "FirstChip / Generic Uninitialized MPtool Controller",
		Category:         "KNOWN_FAKE_TEMPLATE",
		RiskLevel:        "CRITICAL",
		CommonMPtools:    "FirstChip MpTool / DiskGenius",
		DescriptionAR:    "معرف مصنع غير قانوني (FFFF:5678) غير مسجل في منظمة USB-IF، يُستخدم حصرياً في الفلاشات الصينية المقلدة.",
		DescriptionEN:    "Illegal/unassigned USB-IF Vendor ID (FFFF:5678) used exclusively in counterfeit mass-production flash drives.",
	},
	{
		VID:              "FFFF",
		PID:              "1201",
		RegisteredOwner:  "Unassigned / Invalid USB-IF VID (0xFFFF)",
		ActualController: "Norel Systems / Generic Chinese Controller",
		Category:         "KNOWN_FAKE_TEMPLATE",
		RiskLevel:        "CRITICAL",
		CommonMPtools:    "Generic MPtool",
		DescriptionAR:    "معرف مصنع غير قانوني (FFFF:1201) يدل على متحكم صيني مقلد بدون ترخيص USB-IF.",
		DescriptionEN:    "Illegal/unassigned USB-IF Vendor ID (FFFF:1201) indicating an unlicensed generic controller.",
	},
	{
		VID:              "1E3D",
		PID:              "*",
		RegisteredOwner:  "Chipsbank Microelectronics Co., Ltd.",
		ActualController: "Chipsbank CBM2098 / CBM2099 / CBM2199",
		Category:         "KNOWN_FAKE_TEMPLATE",
		RiskLevel:        "HIGH",
		CommonMPtools:    "Chipsbank APTool / UMPTool",
		DescriptionAR:    "متحكم Chipsbank صيني رخيص يُبرمج غالباً بأداة UMPTool لتغيير السعة الظاهرية.",
		DescriptionEN:    "Chipsbank budget controller commonly flashed with UMPTool/APTool to spoof storage capacity.",
	},
	{
		VID:              "1221",
		PID:              "3234",
		RegisteredOwner:  "Micov Microelectronics (Ameco)",
		ActualController: "Micov MXT6208 / MW8209",
		Category:         "KNOWN_FAKE_TEMPLATE",
		RiskLevel:        "CRITICAL",
		CommonMPtools:    "Ameco / Micov UdTools",
		DescriptionAR:    "متحكم Micov MW8209/MXT6208 شهير في الفلاشات المزورة التي تُعيد تدوير شرائح NAND التالفة.",
		DescriptionEN:    "Micov MW8209/MXT6208 controller notorious for counterfeit drives using downgraded/scrap NAND.",
	},
	{
		VID:              "058F",
		PID:              "1234",
		RegisteredOwner:  "Alcor Micro Corp.",
		ActualController: "Alcor Micro AU6989SN (Factory Default PID 1234)",
		Category:         "KNOWN_FAKE_TEMPLATE",
		RiskLevel:        "HIGH",
		CommonMPtools:    "AlcorMP",
		DescriptionAR:    "متحكم Alcor Micro مبرمج بالمعرف الافتراضي 1234 عبر أداة AlcorMP، يُستخدم غالباً في الفلاشات المُعاد برمجتها أو المزورة.",
		DescriptionEN:    "Alcor Micro controller with factory-default PID 1234 flashed via AlcorMP, frequently seen in reprogrammed or fake drives.",
	},

	// === AUTHENTIC TIER-1 BRANDS ===
	{
		VID:              "0781",
		PID:              "*",
		RegisteredOwner:  "SanDisk Corp. (Western Digital)",
		ActualController: "SanDisk Proprietary USB 3.x / 2.0 Controller",
		Category:         "AUTHENTIC_BRAND",
		RiskLevel:        "LOW",
		CommonMPtools:    "Proprietary Factory Locked",
		DescriptionAR:    "معرف SanDisk الرسمي المسجل في منظمة USB-IF.",
		DescriptionEN:    "Official USB-IF Vendor ID registered to SanDisk Corp. (Western Digital).",
	},
	{
		VID:              "0951",
		PID:              "*",
		RegisteredOwner:  "Kingston Technology Company, Inc.",
		ActualController: "Kingston / Phison / Silicon Motion OEM Controller",
		Category:         "AUTHENTIC_BRAND",
		RiskLevel:        "LOW",
		CommonMPtools:    "OEM Locked",
		DescriptionAR:    "معرف Kingston الرسمي المسجل في منظمة USB-IF.",
		DescriptionEN:    "Official USB-IF Vendor ID registered to Kingston Technology.",
	},
	{
		VID:              "04E8",
		PID:              "*",
		RegisteredOwner:  "Samsung Electronics Co., Ltd.",
		ActualController: "Samsung Proprietary Controller",
		Category:         "AUTHENTIC_BRAND",
		RiskLevel:        "LOW",
		CommonMPtools:    "Samsung Magician / Proprietary",
		DescriptionAR:    "معرف Samsung Electronics الرسمي المسجل في منظمة USB-IF.",
		DescriptionEN:    "Official USB-IF Vendor ID registered to Samsung Electronics.",
	},
	{
		VID:              "0930",
		PID:              "*",
		RegisteredOwner:  "Kioxia Corp. (formerly Toshiba Memory)",
		ActualController: "Toshiba / Kioxia Controller",
		Category:         "AUTHENTIC_BRAND",
		RiskLevel:        "LOW",
		CommonMPtools:    "OEM Locked",
		DescriptionAR:    "معرف Toshiba / Kioxia الرسمي المسجل في منظمة USB-IF.",
		DescriptionEN:    "Official USB-IF Vendor ID registered to Toshiba / Kioxia.",
	},
	{
		VID:              "05DC",
		PID:              "*",
		RegisteredOwner:  "Lexar Media, Inc.",
		ActualController: "Lexar OEM Controller",
		Category:         "AUTHENTIC_BRAND",
		RiskLevel:        "LOW",
		CommonMPtools:    "OEM Locked",
		DescriptionAR:    "معرف Lexar Media الرسمي المسجل في منظمة USB-IF.",
		DescriptionEN:    "Official USB-IF Vendor ID registered to Lexar Media.",
	},
	{
		VID:              "8564",
		PID:              "*",
		RegisteredOwner:  "Transcend Information, Inc.",
		ActualController: "Transcend OEM Controller",
		Category:         "AUTHENTIC_BRAND",
		RiskLevel:        "LOW",
		CommonMPtools:    "Transcend JetFlash Recovery",
		DescriptionAR:    "معرف Transcend الرسمي المسجل في منظمة USB-IF.",
		DescriptionEN:    "Official USB-IF Vendor ID registered to Transcend Information.",
	},
	{
		VID:              "125F",
		PID:              "*",
		RegisteredOwner:  "ADATA Technology Co., Ltd.",
		ActualController: "ADATA OEM Controller",
		Category:         "AUTHENTIC_BRAND",
		RiskLevel:        "LOW",
		CommonMPtools:    "OEM Locked",
		DescriptionAR:    "معرف ADATA الرسمي المسجل في منظمة USB-IF.",
		DescriptionEN:    "Official USB-IF Vendor ID registered to ADATA Technology.",
	},
	{
		VID:              "090C",
		PID:              "*",
		RegisteredOwner:  "Silicon Motion, Inc. (SMI)",
		ActualController: "Silicon Motion SM3257 / SM3267 / SM3281",
		Category:         "GENERIC_CONTROLLER",
		RiskLevel:        "MEDIUM",
		CommonMPtools:    "SMI Mass Production Tool (SMIMPTool)",
		DescriptionAR:    "متحكم Silicon Motion التايواني؛ يُستخدم في فلاشات أصلية، ولكنه يُستخدم أيضاً في فلاشات مقلدة إذا كان يحمل اسم VendorCo ProductCode.",
		DescriptionEN:    "Silicon Motion (SMI) controller; used in legitimate OEM drives, but also abused in counterfeit drives when paired with 'VendorCo ProductCode' strings.",
	},
	{
		VID:              "13FE",
		PID:              "*",
		RegisteredOwner:  "Phison Electronics Corp.",
		ActualController: "Phison PS2251 / PS2307",
		Category:         "GENERIC_CONTROLLER",
		RiskLevel:        "MEDIUM",
		CommonMPtools:    "Phison MPALL",
		DescriptionAR:    "متحكم Phison التايواني؛ شائع في الفلاشات التجارية ويُعاد تهيئته عبر أداة Phison MPALL.",
		DescriptionEN:    "Phison Electronics controller; common in commercial drives, programmable via Phison MPALL.",
	},

	// === EXTERNAL HDD / SSD TIER-1 OEM VENDORS & USB-TO-SATA/NVME BRIDGES ===
	{
		VID:              "1058",
		PID:              "*",
		RegisteredOwner:  "Western Digital Technologies, Inc.",
		ActualController: "WD Native USB-SATA / USB-NVMe Bridge (My Passport / Elements / WD_BLACK)",
		Category:         "AUTHENTIC_BRAND",
		RiskLevel:        "LOW",
		CommonMPtools:    "WD Drive Utilities / Factory Locked",
		DescriptionAR:    "معرف Western Digital الرسمي للأقراص الصلبة الخارجية (HDD) وأقراص SSD المحمولة.",
		DescriptionEN:    "Official Western Digital USB Vendor ID for external HDDs and portable SSDs.",
	},
	{
		VID:              "0BC2",
		PID:              "*",
		RegisteredOwner:  "Seagate RSS LLC (Seagate Technology)",
		ActualController: "Seagate USB-to-SATA / NVMe Bridge (Expansion / One Touch / FireCuda)",
		Category:         "AUTHENTIC_BRAND",
		RiskLevel:        "LOW",
		CommonMPtools:    "Seagate SeaTools / Factory Locked",
		DescriptionAR:    "معرف Seagate Technology الرسمي للأقراص الصلبة الخارجية وأقراص SSD.",
		DescriptionEN:    "Official Seagate Technology USB Vendor ID for external HDD and SSD enclosures.",
	},
	{
		VID:              "0480",
		PID:              "*",
		RegisteredOwner:  "Toshiba America / Kioxia Storage",
		ActualController: "Toshiba Canvio USB-SATA Bridge",
		Category:         "AUTHENTIC_BRAND",
		RiskLevel:        "LOW",
		CommonMPtools:    "Factory Locked",
		DescriptionAR:    "معرف Toshiba الرسمي للأقراص الصلبة الخارجية (Canvio Series).",
		DescriptionEN:    "Official Toshiba USB Vendor ID for external portable hard drives (Canvio Series).",
	},
	{
		VID:              "152D",
		PID:              "*",
		RegisteredOwner:  "JMicron Technology Corp.",
		ActualController: "JMicron JMS567 / JMS578 / JMS583 USB 3.x to SATA/NVMe Bridge",
		Category:         "GENERIC_CONTROLLER",
		RiskLevel:        "MEDIUM",
		CommonMPtools:    "JMicronReadWriteFp /FwUpdater",
		DescriptionAR:    "جسر تحويل JMicron USB-to-SATA/NVMe؛ يُستخدم في حاويات الأقراص الخارجية الأصلية ولكنه يُستغل أيضاً في أقراص SSD الخارجية المزيفة.",
		DescriptionEN:    "JMicron USB-to-SATA/NVMe bridge controller; widely used in legitimate external enclosures, but also found in counterfeit portable SSDs.",
	},
	{
		VID:              "174C",
		PID:              "*",
		RegisteredOwner:  "ASMedia Technology Inc.",
		ActualController: "ASMedia ASM1153E / ASM2362 / ASM2464PD USB-to-SATA/NVMe Bridge",
		Category:         "GENERIC_CONTROLLER",
		RiskLevel:        "LOW",
		CommonMPtools:    "ASMedia MPTool",
		DescriptionAR:    "جسر تحويل ASMedia عالي الأداء (SATA/NVMe إلى USB 3.2/USB4).",
		DescriptionEN:    "High-performance ASMedia USB 3.2/USB4 to SATA/NVMe bridge controller.",
	},
	{
		VID:              "0BDA",
		PID:              "*",
		RegisteredOwner:  "Realtek Semiconductor Corp.",
		ActualController: "Realtek RTL9210 / RTL9210B USB 3.2 to NVMe/SATA Bridge or Card Reader",
		Category:         "GENERIC_CONTROLLER",
		RiskLevel:        "LOW",
		CommonMPtools:    "Realtek UTHS / DumpTool",
		DescriptionAR:    "شريحة جسر أو قارئ بطاقات من شركة Realtek التايوانية (RTL9210 NVMe/SATA أو قارئ SD).",
		DescriptionEN:    "Realtek Semiconductor USB-to-NVMe/SATA bridge (RTL9210) or SD/MMC card reader controller.",
	},
	{
		VID:              "2537",
		PID:              "*",
		RegisteredOwner:  "Norelsys Co., Ltd.",
		ActualController: "Norelsys NS1066 / NS1068X USB 3.0 to SATA Bridge",
		Category:         "KNOWN_FAKE_TEMPLATE",
		RiskLevel:        "HIGH",
		CommonMPtools:    "Norelsys MPTool",
		DescriptionAR:    "جسر Norelsys الصيني الرخيص؛ شائع جداً في أقراص SSD الخارجية المزيفة التي بداخلها بطاقة microSD أو فلاش رخيص.",
		DescriptionEN:    "Norelsys budget USB-to-SATA bridge frequently found inside counterfeit portable external SSDs.",
	},
}

var suspiciousSCSIStrings = []string{
	"vendorco",
	"productcode",
	"flash   disk",
	"flash disk 3.0",
	"general udisk",
	"usb     disk",
	"nand    flash",
	"generic flash disk",
}

// LookupController matches VID, PID, and SCSI Inquiry strings against the forensic database.
func LookupController(vid, pid, scsiVendor, scsiProduct string) model.ControllerSignature {
	v := strings.ToUpper(strings.TrimSpace(vid))
	p := strings.ToUpper(strings.TrimSpace(pid))
	combinedSCSI := strings.ToLower(strings.TrimSpace(scsiVendor) + " " + strings.TrimSpace(scsiProduct))

	// 1. Check exact VID + PID match first
	for _, rec := range knownSignatures {
		if rec.VID == v && rec.PID == p {
			return toModel(rec, v, p)
		}
	}

	// 2. Check wildcard VID + "*" match
	for _, rec := range knownSignatures {
		if rec.VID == v && rec.PID == "*" {
			sig := toModel(rec, v, p)
			// Check if SCSI strings betray a generic MPtool template
			for _, susp := range suspiciousSCStrings(combinedSCSI) {
				sig.Category = "KNOWN_FAKE_TEMPLATE"
				sig.RiskLevel = "CRITICAL"
				sig.DescriptionAR += fmt.Sprintf(" (تنبيه: يحتوي نص الاستعلام على البصمة المشبوهة '%s' الخاصة بأدوات التزوير).", susp)
				sig.DescriptionEN += fmt.Sprintf(" (Alert: SCSI string contains suspicious MPtool placeholder '%s').", susp)
				break
			}
			return sig
		}
	}

	// 3. Check if SCSI strings alone match known fake placeholders
	if hits := suspiciousSCStrings(combinedSCSI); len(hits) > 0 {
		return model.ControllerSignature{
			VID:              v,
			PID:              p,
			RegisteredOwner:  "Unverified / Generic USB Vendor",
			ActualController: "Generic MPtool Controller (" + strings.ToUpper(hits[0]) + ")",
			Category:         "KNOWN_FAKE_TEMPLATE",
			RiskLevel:        "HIGH",
			CommonMPtools:    "FirstChip / Chipsbank / SMI MPtool",
			DescriptionAR:    fmt.Sprintf("متحكم يحمل نص استعلام مصنعي عام ('%s') شائع الاستخدام في الفلاشات المقلدة.", scsiVendor+" "+scsiProduct),
			DescriptionEN:    fmt.Sprintf("Controller carries generic factory placeholder string ('%s') common in counterfeit drives.", scsiVendor+" "+scsiProduct),
		}
	}

	return model.ControllerSignature{
		VID:              v,
		PID:              p,
		RegisteredOwner:  "Unknown / Generic USB Storage",
		ActualController: "Standard USB Mass Storage Controller",
		Category:         "UNKNOWN",
		RiskLevel:        "MEDIUM",
		CommonMPtools:    "Unknown",
		DescriptionAR:    "معرف غير مدرج في قائمة القوالب المزورة الشهيرة؛ يعتمد الحكم النهائي على فحص السعة الفيزيائية بالبحث الثنائي.",
		DescriptionEN:    "Identifier not in known fake template list; final verdict depends on physical binary-search capacity test.",
	}
}

func suspiciousSCStrings(combined string) []string {
	var out []string
	for _, s := range suspiciousSCSIStrings {
		if strings.Contains(combined, s) {
			out = append(out, s)
		}
	}
	return out
}

func toModel(r VendorRecord, vid, pid string) model.ControllerSignature {
	return model.ControllerSignature{
		VID:              vid,
		PID:              pid,
		RegisteredOwner:  r.RegisteredOwner,
		ActualController: r.ActualController,
		Category:         r.Category,
		RiskLevel:        r.RiskLevel,
		CommonMPtools:    r.CommonMPtools,
		DescriptionAR:    r.DescriptionAR,
		DescriptionEN:    r.DescriptionEN,
	}
}

var ieeeOUIRegistry = map[string]string{
	"00A075": "Micron Technology, Inc.",
	"002538": "Samsung Electronics Co., Ltd.",
	"001B44": "SanDisk Corporation (Western Digital)",
	"0014EE": "Western Digital Technologies, Inc.",
	"000C50": "Seagate Technology LLC",
	"00080D": "Kioxia Corporation (Toshiba Memory)",
	"8CE38E": "Kioxia Corporation",
	"ACE42E": "SK Hynix Inc.",
	"5CD2E4": "Solidigm / Intel Corporation",
	"6479A7": "Phison Electronics Corp.",
	"0026B7": "Kingston Technology Company, Inc.",
}

// ResolveStorageOrigin enriches DriveInfo with true OEM Manufacturer, Controller Vendor, and IEEE OUI across USB, NVMe, SATA SSD, and HDD devices.
func ResolveStorageOrigin(d *model.DriveInfo, usb model.USBTopology, sig model.ControllerSignature) {
	modelUpper := strings.ToUpper(strings.TrimSpace(d.HardwareModel))
	serialClean := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(d.HardwareSerial), "_", ""), ".", ""))

	// 1. Check EUI-64 / WWN Serial for IEEE OUI
	for oui, vendor := range ieeeOUIRegistry {
		if strings.Contains(serialClean, oui) {
			d.IEEEOUI = fmt.Sprintf("%s-%s-%s (%s)", oui[0:2], oui[2:4], oui[4:6], vendor)
			if d.OEMManufacturer == "" {
				d.OEMManufacturer = vendor
			}
			break
		}
	}

	// 2. Match Model / NVMe / SATA / HDD OEM Signatures
	switch {
	case strings.Contains(modelUpper, "MICRON") || strings.HasPrefix(modelUpper, "MTFD") || strings.HasPrefix(modelUpper, "CT"):
		d.OEMManufacturer = "Micron Technology, Inc. (Crucial / Micron Fab)"
		if strings.Contains(strings.ToUpper(d.BusType), "NVME") {
			d.ControllerVendor = "Micron Proprietary PCIe Gen4 NVMe Controller (3D TLC NAND)"
		} else {
			d.ControllerVendor = "Micron / Silicon Motion SATA Controller"
		}
	case strings.Contains(modelUpper, "SAMSUNG") || strings.HasPrefix(modelUpper, "MZ"):
		d.OEMManufacturer = "Samsung Electronics Co., Ltd. (V-NAND Fab)"
		d.ControllerVendor = "Samsung Proprietary Controller (Elpis / Pascal / Phoenix)"
	case strings.Contains(modelUpper, "WD") || strings.Contains(modelUpper, "WESTERN DIGITAL") || strings.Contains(modelUpper, "SANDISK") || strings.HasPrefix(modelUpper, "SN"):
		d.OEMManufacturer = "Western Digital Corp. / SanDisk (BiCS NAND / WD Mechanical)"
		if d.MediaType == "HDD" {
			d.ControllerVendor = "WD Marvell / Proprietary Servo & Channel Controller"
		} else {
			d.ControllerVendor = "WD / SanDisk Proprietary nCache Controller"
		}
	case strings.Contains(modelUpper, "SEAGATE") || strings.HasPrefix(modelUpper, "ST"):
		d.OEMManufacturer = "Seagate Technology LLC"
		if d.MediaType == "HDD" {
			d.ControllerVendor = "Seagate AcuTrac / Proprietary HDD Controller"
		} else {
			d.ControllerVendor = "Seagate / Phison NVMe/SATA Controller"
		}
	case strings.Contains(modelUpper, "KIOXIA") || strings.Contains(modelUpper, "TOSHIBA") || strings.HasPrefix(modelUpper, "THN"):
		d.OEMManufacturer = "Kioxia Corporation (formerly Toshiba Memory)"
		d.ControllerVendor = "Kioxia Proprietary BiCS Flash Controller"
	case strings.Contains(modelUpper, "HYNIX") || strings.HasPrefix(modelUpper, "HFS") || strings.HasPrefix(modelUpper, "HFM"):
		d.OEMManufacturer = "SK Hynix Inc. (4D NAND Fab)"
		d.ControllerVendor = "SK Hynix Aries / Cepheus Proprietary Controller"
	case strings.Contains(modelUpper, "KINGSTON") || strings.HasPrefix(modelUpper, "SKC") || strings.HasPrefix(modelUpper, "SA400"):
		d.OEMManufacturer = "Kingston Technology Company, Inc."
		d.ControllerVendor = "Phison / Silicon Motion OEM Controller"
	case strings.Contains(modelUpper, "YMTC") || strings.Contains(modelUpper, "ZHITAI"):
		d.OEMManufacturer = "Yangtze Memory Technologies Corp. (YMTC Xtacking)"
		d.ControllerVendor = "MaxioTech / YMTC Controller"
	}

	// 3. Fallback to USB Controller Signature when on USB bus or still unresolved
	if d.OEMManufacturer == "" && sig.RegisteredOwner != "" {
		d.OEMManufacturer = sig.RegisteredOwner
	}
	if d.ControllerVendor == "" && sig.ActualController != "" {
		d.ControllerVendor = sig.ActualController
	}
	if d.IEEEOUI == "" {
		if usb.VendorID != "" {
			d.IEEEOUI = fmt.Sprintf("USB-IF VID:%s PID:%s", usb.VendorID, usb.ProductID)
		} else {
			d.IEEEOUI = "N/A (Standard Serial)"
		}
	}
}
