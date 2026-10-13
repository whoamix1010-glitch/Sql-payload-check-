// Package web serves the floppy dashboard: a local browser UI where the
// operator enters a target, picks the SQL injection techniques to run, and
// watches findings stream in live.
package web

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/whoamix1010-glitch/floppy/internal/scanner"
)

//go:embed dashboard.html
var dashboardHTML []byte

type scanRequest struct {
	URL        string   `json:"url"`
	Method     string   `json:"method"`
	Data       string   `json:"data"`
	Cookie     string   `json:"cookie"`
	Delay      int      `json:"delay"`
	Techniques []string `json:"techniques"`
}

// Serve starts the dashboard HTTP server on addr (e.g. "127.0.0.1:8777").
func Serve(addr string) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(dashboardHTML)
	})

	mux.HandleFunc("/api/scan", handleScan)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONLine(w, map[string]string{"error": "bad request: " + err.Error()})
		return
	}

	techs := make([]scanner.Technique, 0, len(req.Techniques))
	for _, t := range req.Techniques {
		techs = append(techs, scanner.Technique(t))
	}

	sc, err := scanner.New(scanner.Options{
		URL:        req.URL,
		Method:     req.Method,
		Data:       req.Data,
		Cookie:     req.Cookie,
		Delay:      req.Delay,
		Techniques: techs,
	})
	if err != nil {
		writeJSONLine(w, map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	flusher, _ := w.(http.Flusher)

	// Bound every scan so a hung target cannot pin the connection open forever.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	for ev := range sc.Run(ctx) {
		if ev.Finding != nil {
			writeJSONLine(w, map[string]any{"finding": ev.Finding})
		} else {
			writeJSONLine(w, map[string]string{"log": ev.Log})
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
	writeJSONLine(w, map[string]bool{"done": true})
	if flusher != nil {
		flusher.Flush()
	}
}

func writeJSONLine(w http.ResponseWriter, v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(w, "%s\n", b)
}
