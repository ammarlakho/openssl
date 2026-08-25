"""Assemble the prompt bundle handed to the LLM.

Reads test/**/*.c once in-process to pick reference tests, avoiding external
tool dependencies (rg/grep/find).

Prompt order:
  1) WHY_YOU_ARE_HERE banner
  2) SOURCE_UNDER_TEST -- the implementation to write tests for
  3) REFERENCE_TESTS   -- short excerpts from other tests (style/API hints)
  4) STUB              -- snippet mode only: the scaffold being filled
  5) RULES             -- full contract, or the snippet-mode contract
  6) WHAT_TO_EMIT      -- the output task
"""

import math
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from . import paths, stub

# Defaults differ between full-module mode and snippet mode.
DEFAULT_REFS = 5
DEFAULT_SNIP_LINES = 120
SNIPPET_REFS = 4
SNIPPET_SNIP_LINES = 50

# Public API symbols worth using as reference-test search terms.
SYMBOL_RE = re.compile(
    r"\b(?:BIO|EVP|SSL|RSA|EC|ASN1|X509|OSSL|CMS|PKCS7|PKCS8|PKCS12|BN|DH|DSA"
    r"|HMAC|CMAC|KDF|RAND|ERR|PEM|OCSP|CONF|CRYPTO|SRP|CT|TS|UI|ENGINE|OPENSSL"
    r"|MD5|SHA|AES|DES|CAMELLIA|CHACHA|POLY1305|SM2|SM3|SM4)"
    r"_[A-Za-z0-9_]+\b"
)
MAX_SYMBOLS = 20

# Relative weights for the different kinds of search term. The file stem is a
# far stronger relevance signal than an incidental API symbol, so scoring must
# not treat them alike (it used to, which buried the obvious reference).
W_STEM = 4.0
W_KEYWORD = 3.0
W_SYMBOL = 1.0
W_DIR = 0.5

# BM25 knobs: k1 damps repeated hits of the same term, b applies length
# normalisation so a 1500-line catch-all does not outrank a focused test
# merely by mentioning more symbols in passing.
BM25_K1 = 1.2
BM25_B = 0.75

# Weight of filename affinity relative to the BM25 content score. The name of
# a test file is the strongest relevance signal there is and content matching
# cannot see it: "bio_enc" does not occur as a whole word inside
# bio_enc_test.c, so body search alone never surfaces the obvious reference.
# Both components are normalised to [0, 1] first, so this reads directly as
# "a perfect name match is worth W_NAME times the best content match".
W_NAME = 1.5
MIN_TOKEN = 3
# _name_affinity returns whole-stem match (0/1) plus token score (0..1).
MAX_AFFINITY = 2.0
# A stem token is only as good a hint as it is rare among test filenames:
# "x509" identifies a handful of files, "lib"/"int"/"test" identify dozens.
# Token credit is its inverse document frequency over candidate filenames,
# scaled so that a token appearing in about this many files scores full marks.
NAME_IDF_PIVOT = 4.0

# Support code, not tests: excerpting these teaches the model nothing about
# how a test is shaped. "generated" is the recommended home for our own output.
EXCLUDED_DIRS = ("helpers", "generated")

# Our own output must never come back as a "reference". No single signal
# catches every case -- generated tests here are committed, so git-tracking
# alone misses them, and they are not all named alike -- so three cheap ones
# are combined: an untracked file, the stub's marker in the body, or a
# generated-looking filename.
GENERATED_NAME_RE = re.compile(r"(?:^|_)(?:generated|llm)(?:_|\.)|^my_generated")
GENERATED_MARKER = "LLM_REPLACE"


class ContextError(Exception):
    """A prompt could not be assembled."""


@dataclass
class ContextOptions:
    """Knobs for prompt assembly; mirrors the shell script's flags."""

    snippet: bool = False
    notes: bool = False
    task: str = ""
    keywords: List[str] = field(default_factory=list)
    # None means "no truncation": the whole source under test goes in. Head
    # truncation loses the end of the file, so it is opt-in only.
    impl_lines: Optional[int] = None
    # None means "use the mode-dependent default".
    refs: Optional[int] = None
    lines: Optional[int] = None
    # Snippet mode: the scaffold the model is filling in.
    stub_path: Optional[str] = None

    @property
    def top_k(self) -> int:
        if self.refs is not None:
            return self.refs
        return SNIPPET_REFS if self.snippet else DEFAULT_REFS

    @property
    def snip_lines(self) -> int:
        if self.lines is not None:
            return self.lines
        return SNIPPET_SNIP_LINES if self.snippet else DEFAULT_SNIP_LINES

    @property
    def rules_doc(self) -> Path:
        return paths.SNIPPET_CONTRACT if self.snippet else paths.CONTRACT


def _read(path: Path) -> str:
    return path.read_text(errors="replace")


def _head(text: str, n: int) -> str:
    return "\n".join(text.splitlines()[:n])


def _section(title: str) -> str:
    return "\n{}\n\n".format(title)


def _require_contracts() -> None:
    for doc in (paths.CONTRACT, paths.SNIPPET_CONTRACT):
        if not doc.is_file():
            raise ContextError("missing contract: {}".format(doc))


def resolve_source(src_arg: str) -> Tuple[Path, str]:
    """Return (absolute path, repo-relative path) for the source under test."""
    src = paths.resolve_under_repo(src_arg)
    if not src.is_file():
        raise ContextError("not a file: {} (resolved from {})".format(src, src_arg))
    try:
        rel = str(src.resolve().relative_to(paths.REPO_ROOT))
    except ValueError:
        rel = str(src)
    return src, rel


def _tracked_tests() -> Optional[frozenset]:
    """Paths of test/**/*.c known to git, or None if git cannot answer.

    Generated tests are untracked, so this is how our own previous output is
    kept out of the reference pool without maintaining a filename blocklist.
    """
    try:
        proc = subprocess.run(
            ["git", "-C", str(paths.REPO_ROOT), "ls-files", "test/**/*.c", "test/*.c"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    names = {line.strip() for line in proc.stdout.splitlines() if line.strip()}
    if not names:
        return None
    return frozenset(paths.REPO_ROOT / name for name in names)


def _is_generated(path: Path, text: str) -> bool:
    """True if this file looks like output from this tool rather than a test."""
    return bool(GENERATED_NAME_RE.search(path.name)) or GENERATED_MARKER in text


def _is_candidate(
    path: Path,
    text: str,
    tracked: Optional[frozenset],
    siblings: frozenset,
) -> bool:
    if any(part in EXCLUDED_DIRS for part in path.parts):
        return False
    if path.name in siblings:
        return False
    if _is_generated(path, text):
        return False
    if tracked is not None and path not in tracked:
        return False
    return True


def _load_test_sources(src_rel: str) -> List[Tuple[Path, str]]:
    """Read every eligible test/**/*.c once so terms can be matched in-process.

    The in-tree test for the file under test is always dropped: it is
    substantially the answer to the question being asked, and feeding it back
    as a "reference" would contaminate any measurement taken here. Both
    spellings are covered -- bio_enc.c -> bio_enc_test.c and
    hmac.c -> hmactest.c -- but only for the exact stem, so a module-wide test
    such as bntest.c still serves as a reference for bn_add.c.
    """
    tracked = _tracked_tests()
    stem = Path(src_rel).stem
    siblings = frozenset(
        {"{}_test.c".format(stem), "{}test.c".format(stem), "{}.c".format(stem)}
    )

    kept: List[Tuple[Path, str]] = []
    for path in sorted(paths.TEST_DIR.rglob("*.c")):
        text = _read(path)
        if _is_candidate(path, text, tracked, siblings):
            kept.append((path, text))
    return kept


@dataclass
class _Term:
    pattern: re.Pattern
    weight: float
    test_only: bool = False


def _search_terms(src_rel: str, src_text: str, keywords: Sequence[str]) -> List[_Term]:
    """Build the weighted term list used to rank candidate reference tests."""
    rel = Path(src_rel)
    terms: List[_Term] = []

    stem = rel.stem
    if stem:
        terms.append(_Term(re.compile(r"\b{}\b".format(re.escape(stem))), W_STEM))

    # The two enclosing directory names (e.g. "evp", "crypto") are weak hints,
    # so restrict those to *_test.c to keep the noise down.
    parents = rel.parent.parts[::-1][:2]
    for token in parents:
        if token in (".", "") or len(token) < 3:
            continue
        terms.append(
            _Term(re.compile(r"\b{}\b".format(re.escape(token))), W_DIR, test_only=True)
        )

    symbols = sorted(set(SYMBOL_RE.findall(src_text)))[:MAX_SYMBOLS]
    for sym in symbols:
        terms.append(_Term(re.compile(re.escape(sym)), W_SYMBOL))

    for kw in keywords:
        kw = kw.strip()
        if kw:
            terms.append(_Term(re.compile(re.escape(kw)), W_KEYWORD))

    return terms


def _name_token_idf(candidates: Sequence[Path]) -> Dict[str, float]:
    """Inverse document frequency of each token across candidate filenames."""
    stems = [c.stem for c in candidates]
    n_docs = max(len(stems), 1)
    cache: Dict[str, float] = {}

    def idf(token: str) -> float:
        if token not in cache:
            df = sum(1 for stem in stems if token in stem)
            cache[token] = math.log(1 + n_docs / (1 + df))
        return cache[token]

    return _IdfLookup(idf, n_docs)


class _IdfLookup(dict):
    """Lazy dict-like wrapper so tokens are only scored when first seen."""

    def __init__(self, fn, n_docs: int):
        super().__init__()
        self._fn = fn
        self.n_docs = n_docs

    def __missing__(self, key):
        value = self._fn(key)
        self[key] = value
        return value


def _name_affinity(src_rel: str, cand: Path, idf: Dict[str, float]) -> float:
    """How much a candidate test's *filename* looks like the source's.

    Scored in two parts, each in [0, 1]: whether the whole source stem occurs
    in the candidate name, and how much rarity-weighted token overlap there
    is. Handles both bio_enc.c -> bio_enc_test.c (exact) and
    hmac.c -> hmactest.c / bn_add.c -> bntest.c (run-together names), while
    refusing to be fooled by a_int.c -> ca_internals_test.c, where the only
    shared token is one of the commonest in the tree.
    """
    rel = Path(src_rel)
    src_stem = rel.stem

    cand_stem = cand.stem
    for suffix in ("_test", "test"):
        if cand_stem.endswith(suffix) and len(cand_stem) > len(suffix):
            cand_stem = cand_stem[: -len(suffix)]
            break

    if not src_stem or not cand_stem:
        return 0.0

    whole = 1.0 if src_stem in cand_stem else 0.0

    # The enclosing directory ("asn1", "x509", ...) is the only usable hint
    # for a source whose stem names no test at all, and rarity weighting keeps
    # a generic one such as "crypto" from mattering.
    tokens = [t for t in src_stem.split("_") if len(t) >= MIN_TOKEN]
    parent = rel.parent.name
    if len(parent) >= MIN_TOKEN and parent not in tokens:
        tokens.append(parent)

    matched = sum(idf[t] for t in dict.fromkeys(tokens) if t in cand_stem)
    n_docs = getattr(idf, "n_docs", 0)
    pivot = math.log(1 + n_docs / (1 + NAME_IDF_PIVOT)) if n_docs else 0.0
    partial = min(1.0, matched / pivot) if pivot > 0 else 0.0

    return whole + partial


def _pick_references(src_abs: Path, src_rel: str, opts: ContextOptions) -> List[Path]:
    """Rank candidate tests by weighted BM25 over the search terms.

    Presence-counting biased the ranking towards whichever file was longest,
    because length alone makes an incidental match of many symbols likely.
    BM25 supplies both the length normalisation and -- via IDF computed over
    the test corpus itself -- an automatic discount for terms like BIO_ctrl
    that appear nearly everywhere. Filename affinity is added on top, since
    the body of a test rarely spells out the source file it exercises.
    """
    sources = _load_test_sources(src_rel)
    if not sources:
        return []

    terms = _search_terms(src_rel, _read(src_abs), opts.keywords)
    lengths = {path: max(len(text.splitlines()), 1) for path, text in sources}
    avgdl = sum(lengths.values()) / len(lengths)

    scores: Dict[Path, float] = {path: 0.0 for path, _ in sources}
    for term in terms:
        eligible = [
            (path, text)
            for path, text in sources
            if not term.test_only or path.name.endswith("_test.c")
        ]
        freqs = {path: len(term.pattern.findall(text)) for path, text in eligible}
        df = sum(1 for count in freqs.values() if count)
        if df == 0:
            continue
        n_docs = len(eligible)
        idf = math.log(1 + (n_docs - df + 0.5) / (df + 0.5))
        for path, freq in freqs.items():
            if not freq:
                continue
            norm = BM25_K1 * (1 - BM25_B + BM25_B * lengths[path] / avgdl)
            scores[path] += term.weight * idf * (freq * (BM25_K1 + 1)) / (freq + norm)

    top = max(scores.values()) if scores else 0.0
    idf = _name_token_idf([path for path, _ in sources])
    for path in scores:
        content = scores[path] / top if top > 0 else 0.0
        name = _name_affinity(src_rel, path, idf) / MAX_AFFINITY
        scores[path] = content + W_NAME * name

    ranked = sorted(
        ((path, score) for path, score in scores.items() if score > 0),
        key=lambda kv: (-kv[1], str(kv[0])),
    )
    return [path for path, _ in ranked[: opts.top_k]]


def _blank_stub_body(text: str) -> str:
    """Reset the marked region to the placeholder a fresh stub carries.

    Splicing writes the model's body back into the same file, so on a second
    run the stub would otherwise show the previous run's answer and every
    generation after the first would be conditioned on the one before it.
    """
    begin, end = stub.BEGIN_MARKER, stub.END_MARKER
    if begin not in text or end not in text:
        return text

    out: List[str] = []
    skipping = False
    for line in text.splitlines():
        if not skipping and begin in line:
            out.append(line)
            indent = line[: len(line) - len(line.lstrip())]
            out.append("{}return TEST_true(1);".format(indent))
            skipping = True
            continue
        if skipping:
            if end in line:
                skipping = False
                out.append(line)
            continue
        out.append(line)
    return "\n".join(out) + "\n"


def _stub_text(opts: ContextOptions) -> Optional[Tuple[str, str]]:
    """Return (relative path, contents) of the stub being filled, if any."""
    if not opts.stub_path:
        return None
    path = paths.resolve_under_repo(opts.stub_path)
    if not path.is_file():
        raise ContextError("stub not found: {}".format(path))
    try:
        rel = str(path.resolve().relative_to(paths.REPO_ROOT))
    except ValueError:
        rel = str(path)
    return rel, _blank_stub_body(_read(path))


def build_prompt(src_arg: str, opts: ContextOptions) -> str:
    """Assemble the full prompt for the source file at src_arg."""
    _require_contracts()
    src_abs, src_rel = resolve_source(src_arg)
    out: List[str] = []

    out.append(_section("=== WHY_YOU_ARE_HERE ==="))
    out.append(
        "Implement or extend automated tests **for behaviors implemented in "
        "SOURCE_UNDER_TEST** ({}).\n".format(src_rel)
    )
    out.append(
        "REFERENCE_TESTS are **other tests** copied in short excerpts: style "
        "and public API hints only—not a solution scaffold.\n"
    )
    if opts.snippet:
        out.append(
            "**Snippet mode**: the STUB section below is the exact file being "
            "compiled. Its includes and setup_tests already exist; your output "
            "replaces only the BEGIN_LLM_REPLACE ... END_LLM_REPLACE block.\n"
        )
    if opts.task:
        out.append("\nScenario: {}\n".format(opts.task))

    out.append(_section("=== SOURCE_UNDER_TEST ({}) ===".format(src_rel)))
    src_text = _read(src_abs)
    total = len(src_text.splitlines())
    if opts.impl_lines is None or total <= opts.impl_lines:
        out.append(src_text if src_text.endswith("\n") else src_text + "\n")
    else:
        # Truncation takes the head, so it drops the tail of the file -- often
        # exactly the branch-heavy ctrl/cleanup functions that carry the most
        # mutants. Only ever do it when explicitly asked.
        out.append(_head(src_text, opts.impl_lines) + "\n")
        out.append(
            "// ... truncated to first {} of {} lines by --impl-lines; drop "
            "the flag for the entire file\n".format(opts.impl_lines, total)
        )

    out.append(
        _section(
            "=== REFERENCE_TESTS (pattern hints — first {} lines each — not "
            "SOURCE_UNDER_TEST) ===".format(opts.snip_lines)
        )
    )
    for ref in _pick_references(src_abs, src_rel, opts):
        rel = ref.relative_to(paths.REPO_ROOT)
        out.append("// --- begin excerpt {} ---\n".format(rel))
        out.append(_head(_read(ref), opts.snip_lines) + "\n")
        out.append("// --- end excerpt {} ---\n\n".format(rel))

    stub = _stub_text(opts)
    if stub is not None:
        rel, text = stub
        out.append(
            _section(
                "=== STUB ({}) — the file being compiled; you fill the marked "
                "block ===".format(rel)
            )
        )
        out.append(text if text.endswith("\n") else text + "\n")
        out.append(
            "\n// Only the headers #included above are available. If you need "
            "another one, say so in a comment rather than adding it.\n"
        )

    out.append(_section("=== RULES ({}) ===".format(opts.rules_doc)))
    out.append(_read(opts.rules_doc))

    if opts.notes:
        out.append(_section("=== NOTES (*.md filenames at repo root) ==="))
        for note in sorted(paths.REPO_ROOT.glob("NOTES*.md")):
            out.append(note.name + "\n")

    out.append(_section("=== WHAT_TO_EMIT ==="))
    if opts.snippet:
        out.append(
            "- Replace ONLY the code between BEGIN_LLM_REPLACE / "
            "END_LLM_REPLACE in the STUB above.\n"
            "- One cohesive test function body; TEST_* asserts; returns 1 on "
            "success, 0 on failure.\n"
            "- No markdown, no narration, no #include/crypto/* fake headers.\n"
        )
    else:
        out.append(
            "Emit ONE complete compilable unit test module (.c): follow "
            "RULES; cover {} behavior.\n"
            "Output: plain C source only — no markdown fences, no stray "
            "escape characters.\n".format(src_rel)
        )

    return "".join(out)


def build_contract_only(opts: ContextOptions) -> str:
    """Just the rules document, for inspecting what the model is told."""
    _require_contracts()
    return _section("=== RULES ({}) ===".format(opts.rules_doc)) + _read(opts.rules_doc)
