package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/whoamix1010-glitch/floppy/internal/scanner"
)

// runInteractive is the default experience: it prints the banner, asks for a
// target URL, then shows a numbered menu of which SQL injection check to run.
// It stays on screen in a loop until the user chooses to exit.
func runInteractive() {
	in := bufio.NewReader(os.Stdin)
	fmt.Print(banner)

	if !confirmAuthorization(false) {
		fmt.Println("\n[!] Aborting. Only test systems you are authorized to test.")
		return
	}

	url := ""
	for {
		if url == "" {
			url = ask(in, "\nEnter target URL (e.g. http://site/item?id=1): ")
			if url == "" {
				fmt.Println("[!] URL cannot be empty.")
				continue
			}
		}

		fmt.Printf("\n  Target: %s\n", url)
		fmt.Println("  ------------------------------------------------")
		fmt.Println("  Which check do you want to run?")
		fmt.Println("    1) Normal / basic payloads   (error-based quick check)")
		fmt.Println("    2) Boolean-based blind       (TRUE vs FALSE response)")
		fmt.Println("    3) Time-based blind          (SLEEP / delay payloads)")
		fmt.Println("    4) Full scan                 (all techniques)")
		fmt.Println("    5) Change target URL")
		fmt.Println("    0) Exit")
		choice := ask(in, "  > ")

		var techs []scanner.Technique
		switch choice {
		case "1":
			techs = []scanner.Technique{scanner.Error}
		case "2":
			techs = []scanner.Technique{scanner.Boolean}
		case "3":
			techs = []scanner.Technique{scanner.Time}
		case "4":
			techs = []scanner.Technique{scanner.Error, scanner.Boolean, scanner.Time}
		case "5":
			url = ""
			continue
		case "0", "q", "exit", "quit":
			fmt.Println("\n[*] bye — whoami · floppy")
			return
		default:
			fmt.Println("  [!] invalid option, pick 0-5.")
			continue
		}

		runScanInteractive(in, url, techs)
	}
}

func runScanInteractive(in *bufio.Reader, url string, techs []scanner.Technique) {
	method := "GET"
	data := ""
	if strings.Contains(strings.ToLower(ask(in, "  POST request? [y/N]: ")), "y") {
		method = "POST"
		data = ask(in, "  POST data (e.g. id=1&name=x): ")
	}
	cookie := ask(in, "  Cookie (optional, Enter to skip): ")

	sc, err := scanner.New(scanner.Options{
		URL:        url,
		Method:     method,
		Data:       data,
		Cookie:     cookie,
		Techniques: techs,
		Delay:      5,
		Timeout:    30 * time.Second,
	})
	if err != nil {
		fmt.Printf("  [!] %v\n", err)
		return
	}

	fmt.Print("\n  [*] scanning...\n\n")
	found := 0
	for ev := range sc.Run(context.Background()) {
		if ev.Finding != nil {
			found++
			f := ev.Finding
			fmt.Printf("  [+] POSSIBLE SQLi  %s (%s)  ->  %s  [DBMS: %s]\n", f.Param, f.Location, f.Technique, f.DBMS)
			fmt.Printf("      payload : %s\n      evidence: %s\n", f.Payload, f.Evidence)
		} else {
			fmt.Printf("      %s\n", ev.Log)
		}
	}
	fmt.Println("  ------------------------------------------------")
	if found == 0 {
		fmt.Println("  [=] No SQL injection detected with this check.")
		fmt.Println("      (A negative result is not proof the target is safe.)")
	} else {
		fmt.Printf("  [=] %d potential injection point(s) found. Verify manually.\n", found)
	}
	ask(in, "\n  Press Enter to return to the menu...")
}

func ask(in *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	line, _ := in.ReadString('\n')
	return strings.TrimSpace(line)
}
