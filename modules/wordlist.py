"""Wordlist generator: dictionary mutations + combinatorial pattern wordlists."""

import itertools
import string

COMMON_MUTATIONS = ["", "123", "1234", "12345", "123456", "2024", "2025", "2026",
                    "!", "@", "#", "$", "%", "1!", "123!", "123!"]


def mutate_words(words, leet=False, min_len=0, max_len=64):
    for word in words:
        word = word.strip()
        if not word:
            continue
        candidates = {word}
        if leet:
            table = str.maketrans({
                "a": "4", "e": "3", "i": "1", "o": "0",
                "s": "5", "t": "7", "l": "1",
                "A": "4", "E": "3", "I": "1", "O": "0",
                "S": "5", "T": "7",
            })
            candidates.add(word.translate(table))
            candidates.add(word.lower().translate(table))
            candidates.add(word.upper().translate(table))
        candidates.update([word.lower(), word.upper(), word.capitalize()])
        for candidate in list(candidates):
            for suffix in COMMON_MUTATIONS:
                for doubled in (candidate, candidate + candidate):
                    for variant in (doubled + suffix, suffix + doubled, doubled):
                        if min_len <= len(variant) <= max_len:
                            yield variant
    yield from ()


def pattern_wordlist(charset, lengths, output=None):
    if output is not None:
        with open(output, "w", encoding="utf-8") as f:
            for length in lengths:
                for combo in itertools.product(charset, repeat=length):
                    f.write("".join(combo) + "\n")
    else:
        for length in lengths:
            for combo in itertools.product(charset, repeat=length):
                yield "".join(combo)


def generate_from_dict(dict_path, output=None, leet=False, min_len=0, max_len=64):
    with open(dict_path, "r", encoding="utf-8", errors="ignore") as d:
        return generate_from_words(d, output=output, leet=leet,
                                   min_len=min_len, max_len=max_len)


def generate_from_words(words, output=None, leet=False, min_len=0, max_len=64):
    if output is not None:
        with open(output, "w", encoding="utf-8") as f:
            count = 0
            seen = set()
            for variant in mutate_words(words, leet=leet, min_len=min_len, max_len=max_len):
                if variant in seen:
                    continue
                seen.add(variant)
                f.write(variant + "\n")
                count += 1
        return count
    return mutate_words(words, leet=leet, min_len=min_len, max_len=max_len)
