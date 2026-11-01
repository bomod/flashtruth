package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/flashtruth/flashtruth/internal/hal"
	"github.com/flashtruth/flashtruth/internal/model"
	"github.com/flashtruth/flashtruth/internal/report"
)

//go:embed ui/index.html
var uiFS embed.FS

type Server struct {
	mu         sync.RWMutex
	lastReport *model.AuditReport
}

func NewServer(initialReport *model.AuditReport) *Server {
	return &Server{lastReport: initialReport}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, err := uiFS.ReadFile("ui/index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})

	mux.HandleFunc("/api/drives", func(w http.ResponseWriter, r *http.Request) {
		drives, err := hal.ListDrives()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"drives": []model.DriveInfo{}, "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"drives": drives})
	})

	mux.HandleFunc("/api/last-report", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		rep := s.lastReport
		s.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if rep == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(rep)
	})

	// SSE endpoint for real-time scan progress + final report
	mux.HandleFunc("/api/scan-stream", func(w http.ResponseWriter, r *http.Request) {
		drive := r.URL.Query().Get("drive")
		if drive == "" {
			http.Error(w, "missing drive parameter", http.StatusBadRequest)
			return
		}
		speedMB, _ := strconv.Atoi(r.URL.Query().Get("speed_mb"))
		if speedMB <= 0 {
			speedMB = 8
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		flusher, ok := w.(http.Flusher)

		sendEvent := func(evType string, payload any) {
			b, _ := json.Marshal(payload)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evType, string(b))
			if ok {
				flusher.Flush()
			}
		}

		rep, err := report.RunFullAudit(drive, speedMB, func(msg string, pct int) {
			sendEvent("progress", map[string]any{"message": msg, "percent": pct})
		})
		if err != nil {
			sendEvent("error", map[string]any{"error": err.Error()})
			return
		}

		s.mu.Lock()
		s.lastReport = rep
		s.mu.Unlock()

		sendEvent("complete", rep)
	})

	mux.HandleFunc("/api/export-html", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		rep := s.lastReport
		s.mu.RUnlock()
		if rep == nil {
			http.Error(w, "No audit report available yet", http.StatusNotFound)
			return
		}
		lang := r.URL.Query().Get("lang")
		if lang == "" {
			lang = "en"
		}
		html := report.RenderCertificateHTML(rep, lang)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"FlashTruth_Certificate_%s_%s.html\"", rep.ReportID, lang))
		_, _ = w.Write([]byte(html))
	})

	mux.HandleFunc("/api/export-json", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		rep := s.lastReport
		s.mu.RUnlock()
		if rep == nil {
			http.Error(w, "No audit report available yet", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"FlashTruth_Audit_%s.json\"", rep.ReportID))
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	})

	mux.HandleFunc("/api/repair", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.mu.RLock()
		rep := s.lastReport
		s.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if rep == nil || !rep.RepairPlan.Needed {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "No counterfeit drive repair plan active"})
			return
		}
		if err := hal.ExecuteLiveHardwareClamp(rep.Drive, rep.RepairPlan.RecommendedSafeBytes, "FLASH_32GB"); err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":       true,
			"safe_gib": rep.RepairPlan.RecommendedSafeGiB,
			"safe_mb":  rep.RepairPlan.RecommendedSafeMB,
			"drive":    rep.Drive.DevicePath,
		})
	})

	return mux
}
