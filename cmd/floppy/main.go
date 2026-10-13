// Command floppy is a SQL injection checker for authorized penetration testing.
//
// Run with no arguments to launch the browser dashboard (whoami · floppy),
// where you pick a target and the injection techniques to run. Use the `scan`
// subcommand for headless/CLI scanning.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/whoamix1010-glitch/floppy/internal/scanner"
	"github.com/whoamix1010-glitch/floppy/internal/web"
)

const banner = `
   ___ _
  / _ | |___  ___ ___ __ _  _
 |  _/ / _ \/ _ \ _ \ _ \ || |
 |_| |_\___/ .__/ .__/ .__/\_, |
           |_|  |_|  |_|   |__/   whoami · floppy
  SQL injection checker — authorized testing only
  github.com/whoamix1010-glitch
`

func main() {
	if len(os.Args) < 2 {
		runDashboard([]string{}) // no args → dashboard
		return
	}
	switch os.Args[1] {
	case "dash", "dashboard", "ui":
		runDashboard(os.Args[2:])
	case "scan":
		runScan(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	case "version", "--version", "-v":
		fmt.Println("floppy 1.0.0 — whoami · floppy")
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Print(banner)
	fmt.Print(`
Usage:
  floppy                 launch the dashboard (default)
  floppy dash [--addr]   launch the dashboard explicitly
  floppy scan  -u URL    run a scan from the command line
  floppy version

Run 'floppy scan -h' for scan options.
`)
}

func runDashboard(args []string) {
	fs := flag.NewFlagSet("dash", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8777", "address to bind the dashboard")
	noOpen := fs.Bool("no-open", false, "do not auto-open the browser")
	fs.Parse(args)

	fmt.Print(banner)
	url := "http://" + *addr
	fmt.Printf("\n[*] Dashboard running at %s\n", url)
	fmt.Println("[*] Press Ctrl+C to stop.")
	if !*noOpen {
		openBrowser(url)
	}
	if err := web.Serve(*addr); err != nil {
		fmt.Fprintf(os.Stderr, "[!] server error: %v\n", err)
		os.Exit(1)
	}
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	url := fs.String("u", "", "target URL (include query params for GET)")
	method := fs.String("m", "GET", "HTTP method: GET or POST")
	data := fs.String("d", "", "POST body, e.g. 'id=1&name=x'")
	tech := fs.String("technique", "error,boolean,time", "comma list: error,boolean,time")
	delay := fs.Int("delay", 5, "seconds for time-based payloads")
	timeout := fs.Int("timeout", 30, "per-request timeout (seconds)")
	throttle := fs.Int("throttle", 0, "milliseconds to wait between requests")
	cookie := fs.String("cookie", "", "Cookie header value")
	ua := fs.String("user-agent", "", "custom User-Agent")
	proxy := fs.String("proxy", "", "proxy URL, e.g. http://127.0.0.1:8080")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification")
	yes := fs.Bool("yes", false, "skip the authorization prompt")
	header := multiFlag{}
	fs.Var(&header, "H", "extra header 'Name: value' (repeatable)")
	fs.Parse(args)

	if *url == "" {
		fmt.Fprintln(os.Stderr, "[!] -u URL is required")
		fs.Usage()
		os.Exit(2)
	}

	fmt.Print(banner)
	if !confirmAuthorization(*yes) {
		fmt.Fprintln(os.Stderr, "[!] Aborting. Only test systems you are authorized to test.")
		os.Exit(1)
	}

	techs := parseTechniques(*tech)
	headers := map[string]string{}
	for _, h := range header {
		if k, v, ok := strings.Cut(h, ":"); ok {
			headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}

	sc, err := scanner.New(scanner.Options{
		URL:        *url,
		Method:     *method,
		Data:       *data,
		Techniques: techs,
		Delay:      *delay,
		Timeout:    time.Duration(*timeout) * time.Second,
		Throttle:   time.Duration(*throttle) * time.Millisecond,
		Headers:    headers,
		Cookie:     *cookie,
		UserAgent:  *ua,
		Proxy:      *proxy,
		Insecure:   *insecure,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n[*] Target : %s\n[*] Tests  : %s\n\n", *url, *tech)
	found := 0
	for ev := range sc.Run(context.Background()) {
		if ev.Finding != nil {
			found++
			f := ev.Finding
			fmt.Printf("[+] POSSIBLE SQLi  %s (%s)  ->  %s  [DBMS: %s]\n", f.Param, f.Location, f.Technique, f.DBMS)
			fmt.Printf("    payload : %s\n    evidence: %s\n", f.Payload, f.Evidence)
		} else {
			fmt.Printf("    %s\n", ev.Log)
		}
	}

	fmt.Println(strings.Repeat("=", 60))
	if found == 0 {
		fmt.Println("[=] No SQL injection detected with the selected techniques.")
		fmt.Println("    (A negative result is not proof the target is safe.)")
	} else {
		fmt.Printf("[=] %d potential injection point(s) found. Verify manually before reporting.\n", found)
		os.Exit(1)
	}
}

func parseTechniques(s string) []scanner.Technique {
	var out []scanner.Technique
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(strings.ToLower(t))
		switch scanner.Technique(t) {
		case scanner.Error, scanner.Boolean, scanner.Time:
			out = append(out, scanner.Technique(t))
		case "":
		default:
			fmt.Fprintf(os.Stderr, "[!] unknown technique %q (use error,boolean,time)\n", t)
			os.Exit(2)
		}
	}
	return out
}

func confirmAuthorization(assumeYes bool) bool {
	if assumeYes {
		return true
	}
	fmt.Print("\nThis tool is for AUTHORIZED security testing only.\n")
	fmt.Print("Do you have written permission to test this target? [y/N] ")
	var ans string
	fmt.Scanln(&ans)
	ans = strings.ToLower(strings.TrimSpace(ans))
	return ans == "y" || ans == "yes"
}

func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default: // linux, including Kali
		cmd = "xdg-open"
	}
	_ = exec.Command(cmd, append(args, url)...).Start() // best-effort; ignore if headless
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
