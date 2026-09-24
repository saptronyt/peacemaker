"""Hash operations: generate hashes and crack them via wordlist/dictionary."""

import hashlib
import itertools
import time
from pathlib import Path

SUPPORTED_ALGOS = sorted(hashlib.algorithms_available)
COMMON_ALGOS = [
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3_256",
    "sha3_512",
    "blake2b",
    "blake2s",
]


def get_hasher(algorithm):
    algorithm = algorithm.lower()
    try:
        return hashlib.new(algorithm)
    except ValueError as exc:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. Use one of: {', '.join(SUPPORTED_ALGOS)}"
        ) from exc


def hash_string(text, algorithm="sha256", salt="", rounds=1):
    hasher = get_hasher(algorithm)
    rounds = max(1, int(rounds))
    for i in range(rounds):
        hasher = get_hasher(algorithm)
        if salt:
            hasher.update((salt + text + salt).encode())
        else:
            hasher.update(text.encode())
        text = hasher.hexdigest()
    return hasher.hexdigest()


def hash_file(path, algorithm="sha256"):
    hasher = get_hasher(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def crack_hash(target, algorithm, wordlist, quiet=False, progress=None):
    target = target.lower().strip()
    guesses = 0
    start = time.time()

    def check(word):
        nonlocal guesses
        guesses += 1
        if progress and guesses % 1000 == 0:
            progress(guesses)
        if hash_string(word, algorithm) == target:
            return True
        return False

    for line in wordlist:
        word = line.strip()
        if not word:
            continue
        if check(word):
            elapsed = time.time() - start
            if not quiet:
                print(
                    f"[+] Hash cracked in {elapsed:.2f}s after {guesses} guesses: "
                    f"'{word}'"
                )
            return word
        if not quiet and progress is None and guesses % 100000 == 0:
            print(f"[*] {guesses} guesses so far...")
    elapsed = time.time() - start
    if not quiet:
        print(f"[-] Not found in {guesses} guesses ({elapsed:.2f}s).")
    return None


def crack_from_file(target, algorithm, wordlist_path, quiet=False, progress=None):
    wordlist_path = Path(wordlist_path)
    if not wordlist_path.is_file():
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")
    with wordlist_path.open("r", encoding="utf-8", errors="ignore") as f:
        return crack_hash(target, algorithm, f, quiet=quiet, progress=progress)


def brute_force(target, algorithm, charset, max_len, quiet=False, progress=None):
    target = target.lower().strip()
    guesses = 0
    start = time.time()
    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            guesses += 1
            if progress and guesses % 10000 == 0:
                progress(guesses)
            candidate = "".join(combo)
            if hash_string(candidate, algorithm) == target:
                elapsed = time.time() - start
                if not quiet:
                    print(
                        f"[+] Cracked by brute force in {elapsed:.2f}s after "
                        f"{guesses} guesses: '{candidate}'"
                    )
                return candidate
            if not quiet and progress is None and guesses % 1000000 == 0:
                print(f"[*] {guesses} guesses so far...")
    elapsed = time.time() - start
    if not quiet:
        print(f"[-] Brute force exhausted after {guesses} guesses ({elapsed:.2f}s).")
    return None
