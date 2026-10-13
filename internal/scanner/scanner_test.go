package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSimilarity(t *testing.T) {
	if s := similarity("hello world", "hello world"); s != 1.0 {
		t.Fatalf("identical strings: want 1.0, got %v", s)
	}
	if s := similarity("hello world", "completely different text!!"); s > 0.5 {
		t.Fatalf("unlike strings: want <0.5, got %v", s)
	}
	near := similarity("the quick brown fox", "the quick brown fax")
	if near < 0.8 {
		t.Fatalf("near-identical strings: want >0.8, got %v", near)
	}
}

func TestMatchError(t *testing.T) {
	body := "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server"
	if got := matchError(body); got != "MySQL" {
		t.Fatalf("want MySQL, got %q", got)
	}
	if got := matchError("perfectly normal page"); got != "" {
		t.Fatalf("want no match, got %q", got)
	}
}

// A mock target that leaks a MySQL error whenever a quote reaches it.
func TestErrorBasedDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.ContainsAny(id, "'\"`\\") {
			w.Write([]byte("Warning: mysqli_query(): You have an error in your SQL syntax near " + id))
			return
		}
		w.Write([]byte("<html>product " + id + "</html>"))
	}))
	defer srv.Close()

	sc, err := New(Options{
		URL:        srv.URL + "/item?id=1",
		Techniques: []Technique{Error},
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	var findings []Finding
	for ev := range sc.Run(context.Background()) {
		if ev.Finding != nil {
			findings = append(findings, *ev.Finding)
		}
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Technique != Error || findings[0].DBMS != "MySQL" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}
