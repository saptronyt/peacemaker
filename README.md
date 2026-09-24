# PeaceMaker

A green, hacker-style terminal tool for security practice. No special libraries needed — just Python.

## What it does

| Feature | What it means |
|---|---|
| **1. Hash** | Turns text into an unreadable string (e.g. `hello` → `5d41402a...`). Used to protect passwords. |
| **2. Crack hash** | The reverse — tries to find the original text of a hash by guessing. It tests millions of common passwords automatically. |
| **3. Make wordlist** | Builds lots of password guesses from words you give it (e.g. `hello` → `Hello`, `hello123`, `hello!`, ...). |
| **4. Port scan** | Checks a computer for open doors (ports), finds what service is running (like SSH or a web server), and checks for known weak spots. |

Hashes are **one-way** — you can't literally "decrypt" them. Cracking means: try every likely password, hash it, and compare.

## Quick start

```bash
# 1. Download the code
git clone https://github.com/saptronyt/peacemaker.git
cd peacemaker

# 2. (Recommended) get the big password list - helps cracking
curl -L -o rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# 3. Run it
./main.py
```

Running `./main.py` opens a menu. **Just pick a number** — it asks for what it needs.

```
  >> Select: 2          <- crack a hash
  >> Hash: 5d41402abc4b2a76b9719d911017c592
  >> Algorithm: md5
  Using rockyou.txt (133 MB)
  > GUESSES: 4,192,000   elapsed 8.1s
[+] Hash cracked in 8.1s: 'hello'
```

## The 4 things in detail

### 1. Make a hash

```bash
./main.py hash --text hello --algo sha256
```
Output: `sha256('hello') = 2cf24dba...`

`--algo` chooses the method. `./main.py hash --algorithms` lists them all.

### 2. Crack a hash

With the big wordlist (fast):
```bash
./main.py crack --hash 5d41402abc4b2a76b9719d911017c592 --algo md5 --wordlist rockyou.txt
```

Without a wordlist (tries every combo of letters+numbers, good only for short ones):
```bash
./main.py crack --hash 5d41402abc4b2a76b9719d911017c592 --algo md5 --brute --max-len 5
```

> Tip: md5 cracks in seconds. sha256 is much slower. `--max-len 10` on sha256 would take centuries — the tool will warn you.

### 3. Make a wordlist

```bash
# Build from your own words
./main.py wordlist --dict base.txt -o out.lst --leet

# Or build every combination of characters
./main.py wordlist --pattern --charset abc123 --lengths 3,4 -o combo.lst
```

`base.txt` is a plain text file, one word per line. `--leet` turns `admin` into `adm1n` style guesses. The result (`out.lst`) can be fed straight into the cracker.

### 4. Port scan

```bash
# Find open ports
./main.py scan 192.168.1.1 --ports 1-1000

# Open ports + what service is running + known vulnerabilities
./main.py scan 192.168.1.1 --analyze

# Same, but also look up the latest CVEs online
./main.py scan 192.168.1.1 --analyze --online
```

It prints something like:
```
  [+] 192.168.1.1:22   open (SSH)
  [+] 192.168.1.1:80   open (HTTP)

[+] SERVICE DETECTION (banner grabbing)...
  192.168.1.1:22   OpenSSH 8.9

[+] VULNERABILITY MAPPING...
  [!] 192.168.1.1:21 - vsftpd (2.3.4)
      CVE-2011-2523 (backdoor, remote shell)
      Note: Immediately vulnerable - update or isolate.
```

## What is rockyou.txt?

A famous list of **14 million real leaked passwords**. Cracking works best when you try these first. It's ~133MB. GitHub won't let us store it in the repo (files over 100MB are blocked), so you grab it with the `curl` command above and keep it in the PeaceMaker folder. If it's there, the menu notices and uses it automatically.

## Safety

Only use PeaceMaker on computers you own or have **written permission** to test. Scanning or cracking other people's systems is illegal in most places.