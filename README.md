# PeaceMaker

A green-themed hacker-style CLI security tool with three core features:

- **Hash generation & cracking** — hashes text/files (md5, sha1, sha256, sha512, etc.), cracks hashes via wordlist or brute force, with a live matrix-style hacking animation showing real-time guess counts and progress.
- **Wordlist generation** — build password variations from any words (case swaps, numbers, symbols, leet-speak), or create combinatorial pattern lists.
- **Port scanning** — fast threaded TCP scan with **service detection** (banner grabbing) and **vulnerability mapping** (built-in CVE knowledge base + optional online CVE lookup via cve.circl.lu).

Pure Python standard library - no dependencies. Game over.

## Usage

Run the interactive menu:

```bash
./main.py
```

Or use CLI commands directly:

```bash
./main.py hash --text hello --algo sha256
./main.py hash --algorithms

./main.py crack --hash 5d41402abc4b2a76b9719d911017c592 --algo md5 --wordlist rockyou.txt
./main.py crack --hash 5d41402abc4b2a76b9719d911017c592 --algo md5 --brute --max-len 5

./main.py wordlist --dict base.txt -o out.lst --leet
./main.py wordlist --pattern --charset abc123 --lengths 3,4 -o combo.lst

./main.py scan 192.168.1.1 --ports 1-1024 --threads 200 --timeout 0.5 --analyze
./main.py scan 192.168.1.1 --analyze --online
```

## Wordlist (rockyou.txt)

For best hash-cracking results, download the standard rockyou.txt wordlist (14M passwords, ~133MB) and place it in the tool's folder. The interactive menu auto-detects it.

```bash
curl -L -o rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
```

GitHub limits single files to 100MB, so rockyou.txt is excluded from this repo and must be downloaded separately.

## Security note

Use only on systems you own or have explicit permission to test. Port scanning and password cracking against unauthorized targets is illegal in most jurisdictions.