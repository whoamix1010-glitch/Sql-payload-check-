# floppy · SQL injection checker

```
   ___ _
  / _ | |___  ___ ___ __ _  _
 |  _/ / _ \/ _ \ _ \ _ \ || |
 |_| |_\___/ .__/ .__/ .__/\_, |
           |_|  |_|  |_|   |__/   whoami · floppy
```

**floppy** is a fast, single-binary SQL injection checker for **authorized penetration
testing**. Written in Go (no runtime dependencies), it ships as one static binary you can
drop onto Kali/Linux and run. It has both a browser **dashboard** and a headless **CLI**.

Created by **whoami · floppy** — https://github.com/whoamix1010-glitch

> ⚠️ **Authorized use only.** Only test systems you own or have explicit written
> permission to test. Unauthorized testing is illegal in most jurisdictions. A negative
> result is not proof a target is safe, and results may contain false positives — verify
> manually before reporting.

---

## Install (one line, Kali/Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/whoamix1010-glitch/sql-payload-check-/main/install.sh | bash
```

This builds the static binary and installs it to `/usr/local/bin` (or `~/.local/bin`).
Requires `git` and Go ≥ 1.21 — on Kali: `sudo apt install -y golang git`.

### Build from source

```bash
git clone https://github.com/whoamix1010-glitch/sql-payload-check-.git
cd sql-payload-check-
make build        # -> ./bin/floppy
```

---

## Usage

### Interactive menu (default)

```bash
floppy
```

Runs the interactive menu and **stays on screen**. It asks for the target URL first,
then shows a numbered menu of which check to run:

```
  Which check do you want to run?
    1) Normal / basic payloads   (error-based quick check)
    2) Boolean-based blind       (TRUE vs FALSE response)
    3) Time-based blind          (SLEEP / delay payloads)
    4) Full scan                 (all techniques)
    5) Change target URL
    0) Exit
```

Pick a number, see the results, and you're returned to the menu to run another check.

### Dashboard (browser UI)

```bash
floppy dash                         # http://127.0.0.1:8777, opens your browser
floppy dash --addr 127.0.0.1:9000   # custom bind address
floppy dash --no-open               # don't auto-open the browser (headless box)
```

The **whoami · floppy** dashboard lets you enter a target, tick which injection types to
run, and watch findings stream in live.

### CLI

```bash
floppy scan -u 'http://target/item?id=1' --yes
floppy scan -u 'http://target/login' -m POST -d 'user=a&pass=b' --technique error,boolean
floppy scan -u 'http://target/item?id=1' --proxy http://127.0.0.1:8080   # route via Burp/ZAP
```

| Flag | Meaning |
|------|---------|
| `-u` | Target URL (include query params for GET) |
| `-m` | HTTP method: `GET` or `POST` |
| `-d` | POST body, e.g. `id=1&name=x` |
| `--technique` | Comma list: `error,boolean,time` (default all) |
| `--delay` | Seconds for time-based payloads (default 5) |
| `--throttle` | Milliseconds between requests (be polite / dodge rate limits) |
| `-H` | Extra header `Name: value` (repeatable) |
| `--cookie` | Cookie header value |
| `--proxy` | Proxy URL (send traffic through Burp/ZAP) |
| `--insecure` | Skip TLS verification (self-signed lab targets) |
| `--yes` | Skip the authorization prompt |

Exit code is `1` when at least one potential injection point is found, `0` otherwise.

---

## Detection techniques

| Technique | How it works |
|-----------|--------------|
| **error-based** | Injects quote/escape probes and looks for DBMS error fingerprints (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) in the response. |
| **boolean blind** | Sends a TRUE and a FALSE payload and compares response similarity — a reliable difference signals injection. |
| **time blind** | Sends a `SLEEP`/`pg_sleep`/`WAITFOR DELAY` payload and measures the delay, confirming with a second request. |

## Project layout

```
cmd/floppy          CLI entry point + dashboard launcher
internal/scanner    detection engine (stdlib only)
internal/web        dashboard server + embedded HTML UI
install.sh          one-line installer
```

## License

MIT — see [LICENSE](LICENSE).
