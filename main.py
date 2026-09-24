#!/usr/bin/env python3
"""PeaceMaker: hash generation/cracking, wordlist generation, and port scanning."""

import argparse
import contextlib
import io
import random
import re
import socket
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

from modules import hash_tools, portscan, vulns, wordlist

VERSION = "1.2.0"

GREEN = "\033[32m"
BRIGHT_GREEN = "\033[92m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
RED = "\033[31m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
CLEAR_LINE = "\033[2K\r"


def c(text, code=GREEN):
    return f"{code}{text}{RESET}"


def type_out(text, delay=0.012):
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\n")


def boot_animation():
    for line in BANNER.splitlines():
        type_out(c(line, RED))
    time.sleep(0.2)
    width = 24
    for i in range(width + 1):
        bar = "#" * i + "-" * (width - i)
        pct = int(i / width * 100)
        sys.stdout.write(f"\r{c('[' + bar + ']', GREEN)} {c(str(pct) + '%', CYAN)}")
        sys.stdout.flush()
        time.sleep(0.04)
    sys.stdout.write("\n\n")
    time.sleep(0.15)


class Spinner:
    def __init__(self, message="Working"):
        self.message = message
        self.frames = ["|", "/", "-", "\\"]
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        def run():
            i = 0
            while not self._stop.is_set():
                frame = self.frames[i % len(self.frames)]
                sys.stdout.write(CLEAR_LINE)
                sys.stdout.write(c(f" {frame} {self.message}...", CYAN))
                sys.stdout.flush()
                time.sleep(0.08)
                i += 1

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def stop(self, msg=""):
        self._stop.set()
        if self._thread:
            self._thread.join()
        sys.stdout.write(CLEAR_LINE)
        sys.stdout.flush()
        if msg:
            print(c(msg, BRIGHT_GREEN))


class HackerSpinner:
    """Matrix-style hacking animation with live progress."""

    LINES = 5

    def __init__(self, target, message="CRACKING", total_getter=None):
        self.target = target
        self.message = message.upper()
        self.total_getter = total_getter
        self.total = None
        self.guesses = 0
        self._start = time.time()
        self._stop = threading.Event()
        self._thread = None

    def update(self, guesses):
        self.guesses = guesses

    def start(self):
        def run():
            for _ in range(self.LINES):
                sys.stdout.write("\n")
            sys.stdout.flush()
            while not self._stop.is_set():
                self._redraw()
                time.sleep(0.06)

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def _redraw(self):
        import random

        if self.total_getter is not None:
            self.total = self.total_getter()

        up = f"\033[{self.LINES}A"
        sys.stdout.write(up)
        elapsed = time.time() - self._start

        sys.stdout.write(CLEAR_LINE)
        sys.stdout.write(c(f"  > TARGET  : {self.target[:64]}", BRIGHT_GREEN))
        sys.stdout.write("\n")

        rain = " ".join(
            "".join(random.choice("0123456789abcdef") for _ in range(4))
            for _ in range(14)
        )
        sys.stdout.write(CLEAR_LINE)
        sys.stdout.write(c(f"  > STREAM  : {rain}", GREEN))
        sys.stdout.write("\n")

        width = 22
        if self.total:
            pct = min(100, int(self.guesses / self.total * 100))
        else:
            pct = 0
        filled = int(pct / 100 * width)
        bar = "#" * filled + "-" * (width - filled)

        sys.stdout.write(CLEAR_LINE)
        sys.stdout.write(c(f"  > STATUS  : {self.message}", CYAN))
        sys.stdout.write("\n")

        sys.stdout.write(CLEAR_LINE)
        sys.stdout.write(
            c(f"  > PROGRESS: [{bar}] {pct}%", YELLOW)
        )
        sys.stdout.write("\n")

        sys.stdout.write(CLEAR_LINE)
        sys.stdout.write(
            c(f"  > GUESSES : {self.guesses:,}   elapsed {elapsed:6.1f}s", GREEN)
        )
        sys.stdout.flush()

    def stop(self, msg=""):
        self._stop.set()
        if self._thread:
            self._thread.join()
        sys.stdout.write(f"\033[{self.LINES}A")
        for _ in range(self.LINES):
            sys.stdout.write(CLEAR_LINE)
            sys.stdout.write("\n")
        sys.stdout.flush()
        if msg:
            print(c(msg, BRIGHT_GREEN))


def run_with_spinner(func, message="Processing", target="", total_getter=None):
    box = {}
    if target:
        spinner = HackerSpinner(target, message, total_getter)
    else:
        spinner = Spinner(message)
    spinner.start()
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            if isinstance(spinner, HackerSpinner):
                func(spinner.update)
            else:
                func()
        box["output"] = buf.getvalue()
        box["error"] = None
    except Exception as exc:
        box["error"] = exc
    finally:
        spinner.stop()
    if box.get("error"):
        print(c(f"[Error] {box['error']}", RED))
    else:
        sys.stdout.write(box.get("output", ""))
        sys.stdout.flush()


def make_parser():
    parser = argparse.ArgumentParser(
        prog="peacemaker",
        description="PeaceMaker - hash generation & cracking, wordlist generation, port scanning.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  peacemaker hash --text hello --algo sha256\n"
            "  peacemaker hash --file /etc/shadow.sample --algo sha512\n"
            "  peacemaker crack --hash 5d41402abc4b2a76b9719d911017c592 --algo md5 --wordlist rockyou.txt\n"
            "  peacemaker crack --hash 5d41402abc4b2a76b9719d911017c592 --algo md5 --brute --charset abc123 --max-len 6\n"
            "  peacemaker wordlist --dict base.txt -o out.lst --leet --min-len 6 --max-len 16\n"
            "  peacemaker wordlist --pattern --charset abc123 --lengths 3,4 -o combo.lst\n"
            "  peacemaker scan 192.168.1.1 --ports 22,80,443\n"
            "  peacemaker scan 192.168.1.1 --ports 1-1024 --threads 200 --timeout 0.5\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    # hash subcommand
    p_hash = sub.add_parser("hash", help="generate a hash from text or a file")
    p_hash.add_argument("--text", help="text to hash")
    p_hash.add_argument("--file", help="file to hash")
    p_hash.add_argument("--algo", default="sha256", help="hash algorithm (default: sha256)")
    p_hash.add_argument("--salt", default="", help="optional salt applied around the text")
    p_hash.add_argument("--rounds", type=int, default=1, help="iterations (default: 1)")
    p_hash.add_argument("--algorithms", action="store_true",
                        help="list all available hash algorithms and exit")

    # crack subcommand
    p_crack = sub.add_parser("crack", help="crack a hash using a wordlist or brute force")
    p_crack.add_argument("--hash", dest="target", required=True, help="the hash to crack")
    p_crack.add_argument("--algo", required=True, help="hash algorithm used")
    p_crack.add_argument("--wordlist", help="path to wordlist file")
    p_crack.add_argument("--brute", action="store_true", help="use brute force instead of wordlist")
    p_crack.add_argument("--charset", default="abcdefghijklmnopqrstuvwxyz0123456789",
                         help="charset for brute force (default: lowercase + digits)")
    p_crack.add_argument("--max-len", type=int, default=6, help="max length for brute force (default: 6)")
    p_crack.add_argument("--quiet", action="store_true", help="suppress progress output")

    # wordlist subcommand
    p_wl = sub.add_parser("wordlist", help="generate wordlists")
    p_wl.add_argument("--dict", help="base dictionary file to mutate")
    p_wl.add_argument("-o", "--output", help="output file (prints to stdout if omitted)")
    p_wl.add_argument("--leet", action="store_true", help="add leet-speak variants")
    p_wl.add_argument("--min-len", type=int, default=0, help="minimum variant length")
    p_wl.add_argument("--max-len", type=int, default=64, help="maximum variant length")
    p_wl.add_argument("--pattern", action="store_true", help="generate combinatorial patterns")
    p_wl.add_argument("--charset", default="abc", help="charset for --pattern (default: abc)")
    p_wl.add_argument("--lengths", default="1,2,3", help="comma-separated lengths for --pattern")

    # scan subcommand
    p_scan = sub.add_parser("scan", help="scan a host for open ports")
    p_scan.add_argument("host", help="target hostname or IP")
    p_scan.add_argument("--ports", default="1-1024",
                        help="ports or ranges, e.g. '22,80,443' or '1-1024' (default: 1-1024)")
    p_scan.add_argument("--timeout", type=float, default=1.0, help="connection timeout in seconds (default: 1.0)")
    p_scan.add_argument("--threads", type=int, default=100, help="number of threads (default: 100)")
    p_scan.add_argument("--top", action="store_true", help="scan the 30 most common ports only")
    p_scan.add_argument("--quiet", action="store_true", help="only print open ports")
    p_scan.add_argument("--analyze", action="store_true",
                        help="service detection (banner grab) + vulnerability mapping")
    p_scan.add_argument("--online", action="store_true",
                        help="query the CVE API for detected services")

    return parser


def cmd_hash(args):
    if args.algorithms:
        print("Available algorithms:")
        for algo in sorted(hash_tools.SUPPORTED_ALGOS):
            print(f"  {algo}")
        return
    if args.text is None and args.file is None:
        print("Error: provide --text or --file", file=sys.stderr)
        sys.exit(1)
    if args.text is not None and args.file is not None:
        print("Error: provide only one of --text or --file", file=sys.stderr)
        sys.exit(1)
    if args.file:
        if not Path(args.file).is_file():
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        digest = hash_tools.hash_file(args.file, args.algo)
        print(f"{args.algo}(file:{args.file}) = {digest}")
    else:
        digest = hash_tools.hash_string(args.text, args.algo, args.salt, args.rounds)
        print(f"{args.algo}('{args.text}') = {digest}")


def cmd_crack(args):
    if not args.brute and not args.wordlist:
        print("Error: provide --wordlist or use --brute", file=sys.stderr)
        sys.exit(1)
    progress = getattr(args, "_progress", None)
    if args.brute:
        hash_tools.brute_force(args.target, args.algo, args.charset, args.max_len,
                               quiet=args.quiet, progress=progress)
    else:
        hash_tools.crack_from_file(args.target, args.algo, args.wordlist,
                                   quiet=args.quiet, progress=progress)


def _count_lines(path):
    try:
        n = 0
        with open(path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                n += chunk.count(b"\n")
        return max(n, 1)
    except OSError:
        return None


def cmd_wordlist(args):
    if args.pattern:
        lengths = [int(x) for x in args.lengths.split(",") if x.strip()]
        if not lengths:
            print("Error: invalid --lengths", file=sys.stderr)
            sys.exit(1)
        if args.output:
            wordlist.pattern_wordlist(args.charset, lengths, output=args.output)
            print(f"Wrote pattern wordlist to {args.output}")
        else:
            for item in wordlist.pattern_wordlist(args.charset, lengths):
                print(item)
        return
    if not args.dict:
        print("Error: provide --dict (base wordlist) or --pattern", file=sys.stderr)
        sys.exit(1)
    if not Path(args.dict).is_file():
        print(f"Error: dictionary not found: {args.dict}", file=sys.stderr)
        sys.exit(1)
    if args.output:
        count = wordlist.generate_from_dict(args.dict, output=args.output, leet=args.leet,
                                            min_len=args.min_len, max_len=args.max_len)
        print(f"Wrote {count} entries to {args.output}")
    else:
        for item in wordlist.generate_from_dict(args.dict, leet=args.leet,
                                                min_len=args.min_len, max_len=args.max_len):
            print(item)


def clean_host(raw):
    host = (raw or "").strip()
    host = re.sub(r"\x1b\[[0-9;]*[a-zA-Z~]", "", host)
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    host = host.split("?", 1)[0]
    host = re.sub(r"[^A-Za-z0-9.\-:]", "", host)
    return host


def cmd_scan(args):
    host = clean_host(args.host)
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Error: cannot resolve host: {host}", file=sys.stderr)
        sys.exit(1)
    if args.top:
        ports = sorted(portscan.COMMON_PORTS.keys())
    else:
        try:
            ports = portscan.parse_ports(args.ports)
        except ValueError as exc:
            print(f"Error: invalid port spec: {exc}", file=sys.stderr)
            sys.exit(1)
    print(f"Scanning {host} ({ip}) on {len(ports)} port(s)...")
    open_ports = portscan.scan_host(ip, ports, timeout=args.timeout,
                                    threads=args.threads, quiet=args.quiet)
    print(f"\nScan complete. {len(open_ports)} open port(s).")
    if not open_ports:
        return open_ports
    if getattr(args, "online", False):
        online_cve_report(ip, open_ports, args.timeout)
    elif getattr(args, "analyze", False):
        analyze_services(ip, open_ports, args.timeout)
    return open_ports


def analyze_services(host, open_ports, timeout=3.0):
    """Service detection (banner grab) + vulnerability mapping."""
    print(c("\n[+] SERVICE DETECTION (banner grabbing)...", CYAN))
    banners = portscan.grab_all(host, open_ports, timeout=timeout)
    findings = {}
    for port in open_ports:
        banner = banners.get(port, "")
        product, version = vulns.parse_banner(port, banner)
        findings[port] = (product, version, banner)
        line = f"  {host}:{port:<6} "
        if product:
            line += c(f"{product}" + (f" {version}" if version else ""), GREEN)
        else:
            line += c("no banner / unknown service", DIM)
        if banner:
            short = next((ln for ln in banner.splitlines() if "Server:" in ln), banner.splitlines()[0])
            line += c(f"  [{short[:60]}]", DIM)
        print(line)

    print(c("\n[+] VULNERABILITY MAPPING...", CYAN))
    hit_any = False
    for port, (product, version, _banner) in findings.items():
        if not product:
            print(f"  {host}:{port:<6} {c('no version info to map', DIM)}")
            continue
        matches = vulns.map_vulnerabilities(product, version)
        if matches:
            hit_any = True
            for entry in matches:
                print(c(f"\n  [!] {host}:{port} - {entry['product']} "
                        f"({version or 'any'})", RED))
                for cve in entry["cves"]:
                    print(c(f"      {cve}", YELLOW))
                print(c(f"      Note: {entry['note']}", DIM))
        else:
            ver = version or ""
            print(f"  {host}:{port:<6} {c(f'{product} {ver} - no known critical CVEs in DB', GREEN)}")
    if not hit_any:
        print(c("\n  No matches in built-in vulnerability DB.", DIM))
        print(c("  Tip: use `--online` flag to query the CVE API.", DIM))


def online_cve_report(host, open_ports, timeout=3.0):
    banners = portscan.grab_all(host, open_ports, timeout=timeout)
    print(c("[+] ONLINE CVE LOOKUP (cve.circl.lu)...", CYAN))
    for port in open_ports:
        product, version = vulns.parse_banner(port, banners.get(port, ""))
        if not product:
            continue
        print(c(f"\n  {host}:{port} - {product} {version or ''}", BRIGHT_GREEN))
        results = vulns.lookup_cve_online(product, version)
        if not results:
            print(c("    (no CVEs returned or API unreachable)", DIM))
        for cve_id, summary in results:
            print(c(f"    {cve_id}: {summary}", YELLOW))


BANNER = r"""
 _____                    __  __       _             
|  __ \                  |  \/  |     | |            
| |__) |__  __ _  ___ ___| \  / | __ _| | _____ _ __ 
|  ___/ _ \/ _` |/ __/ _ \ |\/| |/ _` | |/ / _ \ '__|
| |  |  __/ (_| | (_|  __/ |  | | (_| |   <  __/ |   
|_|   \___|\__,_|\___\___|_|  |_|\__,_|_|\_\___|_|   
   PeaceMaker - hash / wordlist / port scanner
"""

MENU = [
    "1) Generate a hash",
    "2) Crack a hash (wordlist)",
    "3) Crack a hash (brute force)",
    "4) Generate a wordlist",
    "5) Port scan",
    "6) Crack with custom wordlist",
    "0) Exit",
]


def _ask(prompt):
    try:
        return input(c(prompt, CYAN))
    except EOFError:
        raise SystemExit(0)


def _wordlist_to_file(word_list, out):
    count = wordlist.generate_from_words(word_list, output=out)
    print(c(f"Wrote {count} variants to {out}.", BRIGHT_GREEN))


def _fmt_time(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} seconds"
    if seconds < 3600:
        return f"{seconds // 60} minutes {seconds % 60} sec"
    if seconds < 86400:
        return f"{seconds // 3600} hours {(seconds % 3600) // 60} min"
    return f"{seconds // 86400} days {(seconds % 86400) // 3600} hours"


def interactive():
    boot_animation()
    while True:
        print(c(BANNER, RED))
        for item in MENU:
            print("  " + c(item, GREEN))
        choice = _ask("\n  " + c(">>", BRIGHT_GREEN) + " Select: ")
        try:
            if choice == "1":
                text = _ask("  " + c(">>", BRIGHT_GREEN) + " Text: ")
                algo = _ask("  " + c(">>", BRIGHT_GREEN) + " Algorithm [sha256]: ") or "sha256"
                print("  " + "=" * 40)
                run_with_spinner(
                    lambda: cmd_hash(SimpleNamespace(
                        text=text, file=None, algo=algo,
                        salt="", rounds=1, algorithms=False)),
                    f"Generating {algo} hash",
                )
            elif choice == "2":
                target = _ask("  " + c(">>", BRIGHT_GREEN) + " Hash: ")
                algo = _ask("  " + c(">>", BRIGHT_GREEN) + " Algorithm: ")
                if Path("rockyou.txt").is_file():
                    wl = "rockyou.txt"
                    print(c(f"  Using rockyou.txt ({Path('rockyou.txt').stat().st_size // (1024*1024)} MB)", DIM))
                else:
                    wl = _ask("  " + c(">>", BRIGHT_GREEN) + " Wordlist path: ")

                total_box = {"n": None}
                threading.Thread(
                    target=lambda: total_box.__setitem__("n", _count_lines(wl)),
                    daemon=True,
                ).start()

                def crack(p):
                    return cmd_crack(SimpleNamespace(
                        target=target, algo=algo,
                        wordlist=wl, brute=False, quiet=False, _progress=p))

                run_with_spinner(
                    crack, f"Cracking {algo}",
                    target=target,
                    total_getter=lambda: total_box["n"],
                )
            elif choice == "3":
                target = _ask("  " + c(">>", BRIGHT_GREEN) + " Hash: ")
                algo = _ask("  " + c(">>", BRIGHT_GREEN) + " Algorithm: ")
                maxlen = _ask("  " + c(">>", BRIGHT_GREEN) +
                              " Max length (3-4 is fast, 5+ slow) [4]: ") or "4"
                maxlen = int(maxlen)
                charset = "abcdefghijklmnopqrstuvwxyz0123456789"
                combos = sum(len(charset) ** l for l in range(1, maxlen + 1))
                est_s = combos / 500000
                if est_s > 30:
                    print(c(
                        f"\n  [WARNING] {combos:,} combos needed.",
                        YELLOW))
                    print(c(
                        f"  Estimated time for {algo}: "
                        f"{_fmt_time(est_s)}.",
                        YELLOW))
                    sure = _ask("  Continue anyway? (y/n) [n]: ") or "n"
                    if sure.lower() != "y":
                        print(c("  Aborted.", RED))
                        return

                def brute(p):
                    return cmd_crack(SimpleNamespace(
                        target=target, algo=algo, wordlist=None,
                        brute=True, charset=charset, max_len=maxlen,
                        quiet=False, _progress=p))

                run_with_spinner(
                    brute, f"Brute forcing {algo}",
                    target=target,
                )
            elif choice == "4":
                words = _ask("  " + c(">>", BRIGHT_GREEN) +
                             " Type your words (space separated): ")
                out = _ask("  " + c(">>", BRIGHT_GREEN) +
                           " Output file (Enter = print to screen): ") or None
                word_list = [w for w in words.split() if w.strip()]
                if not word_list:
                    print(c("  [ERROR] No words given.", RED))
                    return
                if out:
                    run_with_spinner(
                        lambda: _wordlist_to_file(word_list, out),
                        "Generating wordlist",
                    )
                else:
                    count = 0
                    for item in wordlist.mutate_words(word_list):
                        print(item)
                        count += 1
                    print(c(f"  Generated {count} variants.", CYAN))
            elif choice == "5":
                host = clean_host(_ask("  " + c(">>", BRIGHT_GREEN) + " Target host: "))
                ports = _ask("  " + c(">>", BRIGHT_GREEN) + " Ports [1-1024]: ") or "1-1024"
                found = {}
                run_with_spinner(
                    lambda: found.setdefault("ports", cmd_scan(SimpleNamespace(
                        host=host, ports=ports, timeout=1.0,
                        threads=100, top=False, quiet=False,
                        analyze=True, online=False))),
                    f"Scanning {host}",
                )
                open_ports = found.get("ports") or []
                if open_ports:
                    online = _ask("  " + c(">>", BRIGHT_GREEN) +
                                  " Online CVE lookup? (y/n) [n]: ") or "n"
                    if online.lower() == "y":
                        run_with_spinner(
                            lambda: online_cve_report(host, open_ports, 3.0),
                            f"Querying CVE database",
                        )
            elif choice == "6":
                target = _ask("  " + c(">>", BRIGHT_GREEN) + " Hash: ")
                algo = _ask("  " + c(">>", BRIGHT_GREEN) + " Algorithm: ")
                words = _ask("  " + c(">>", BRIGHT_GREEN) +
                             " Type words to try (space separated): ")
                word_list = [w for w in words.split() if w.strip()]
                if not word_list:
                    print(c("  [ERROR] No words given.", RED))
                    return
                wl = "custom_wordlist.lst"
                print(c(f"  Building wordlist from: {', '.join(word_list)}", DIM))
                run_with_spinner(
                    lambda: _wordlist_to_file(word_list, wl),
                    "Building wordlist",
                )
                total_box = {"n": None}
                threading.Thread(
                    target=lambda: total_box.__setitem__("n", _count_lines(wl)),
                    daemon=True,
                ).start()

                def crack(p):
                    return cmd_crack(SimpleNamespace(
                        target=target, algo=algo,
                        wordlist=wl, brute=False, quiet=False, _progress=p))

                run_with_spinner(
                    crack, f"Cracking {algo}",
                    target=target,
                    total_getter=lambda: total_box["n"],
                )
            elif choice == "0":
                type_out(c("\n  [SHUTDOWN] Terminating session...", YELLOW), 0.03)
                time.sleep(0.3)
                print(c("  Goodbye.", BRIGHT_GREEN))
                break
            else:
                print(c("  [ERROR] Invalid choice.", RED))
        except (ValueError, FileNotFoundError) as exc:
            print(c(f"  [Error] {exc}", RED))
        print("\n" + "=" * 40)


def main():
    if len(sys.argv) == 1:
        try:
            interactive()
        except KeyboardInterrupt:
            print(c("\n  Goodbye.", BRIGHT_GREEN))
        return
    args = make_parser().parse_args()
    try:
        if args.command == "hash":
            cmd_hash(args)
        elif args.command == "crack":
            cmd_crack(args)
        elif args.command == "wordlist":
            cmd_wordlist(args)
        elif args.command == "scan":
            cmd_scan(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
