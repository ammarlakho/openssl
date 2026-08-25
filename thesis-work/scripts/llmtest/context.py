"""Assemble the prompt bundle handed to the LLM.

Reads test/**/*.c once in-process to pick reference tests, avoiding external
tool dependencies (rg/grep/find).

Prompt order:
  1) WHY_YOU_ARE_HERE banner
  2) SOURCE_UNDER_TEST -- the implementation to write tests for
  3) REFERENCE_TESTS   -- short excerpts from other tests (style/API hints)
  4) RULES             -- full contract, or the snippet-mode contract
  5) WHAT_TO_EMIT      -- the output task
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from . import paths

# Defaults differ between full-module mode and snippet mode.
DEFAULT_REFS = 5
DEFAULT_SNIP_LINES = 120
SNIPPET_REFS = 4
SNIPPET_SNIP_LINES = 50
DEFAULT_IMPL_LINES = 280

# Public API symbols worth using as reference-test search terms.
SYMBOL_RE = re.compile(
    r"\b(?:BIO|EVP|SSL|RSA|EC|ASN1|X509|OSSL|CMS|PKCS7)_[A-Za-z0-9_]+\b"
)
MAX_SYMBOLS = 20

# Our own generated output must never be fed back in as a "reference".
EXCLUDED_REFERENCES = frozenset(
    {
        "generated_test.c",
        "generated_test_backup.c",
        "generated_test_cursor.c",
        "my_generated.c",
    }
)


class ContextError(Exception):
    """A prompt could not be assembled."""


@dataclass
class ContextOptions:
    """Knobs for prompt assembly; mirrors the shell script's flags."""

    snippet: bool = False
    full_source: bool = False
    notes: bool = False
    task: str = ""
    keywords: List[str] = field(default_factory=list)
    impl_lines: int = DEFAULT_IMPL_LINES
    # None means "use the mode-dependent default".
    refs: Optional[int] = None
    lines: Optional[int] = None

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


def _load_test_sources() -> List[Tuple[Path, str]]:
    """Read every test/**/*.c once so search terms can be matched in-process."""
    return [(p, _read(p)) for p in sorted(paths.TEST_DIR.rglob("*.c"))]


def _search_terms(src_rel: str, src_text: str, keywords: Sequence[str]) -> List[Tuple[re.Pattern, bool]]:
    """Build (pattern, test_files_only) pairs, in the shell script's order."""
    rel = Path(src_rel)
    terms: List[Tuple[re.Pattern, bool]] = []

    stem = rel.stem
    if stem:
        terms.append((re.compile(r"\b{}\b".format(re.escape(stem))), False))

    # The two enclosing directory names (e.g. "evp", "crypto") are weak hints,
    # so restrict those to *_test.c to keep the noise down.
    parents = rel.parent.parts[::-1][:2]
    for token in parents:
        if token in (".", "") or len(token) < 3:
            continue
        terms.append((re.compile(r"\b{}\b".format(re.escape(token))), True))

    symbols = sorted(set(SYMBOL_RE.findall(src_text)))[:MAX_SYMBOLS]
    for sym in symbols:
        terms.append((re.compile(re.escape(sym)), False))

    for kw in keywords:
        kw = kw.strip()
        if kw:
            terms.append((re.compile(re.escape(kw)), False))

    return terms


def _pick_references(src_abs: Path, src_rel: str, opts: ContextOptions) -> List[Path]:
    """Rank test files by how many search terms they match; keep the top K."""
    sources = _load_test_sources()
    terms = _search_terms(src_rel, _read(src_abs), opts.keywords)

    hits: Dict[Path, int] = {}
    for pattern, test_only in terms:
        for path, text in sources:
            if test_only and not path.name.endswith("_test.c"):
                continue
            if path.name in EXCLUDED_REFERENCES:
                continue
            if pattern.search(text):
                hits[path] = hits.get(path, 0) + 1

    ranked = sorted(hits.items(), key=lambda kv: (-kv[1], str(kv[0])))
    return [path for path, _ in ranked[: opts.top_k]]


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
            "**Snippet mode**: assume the stub generator already produced "
            "includes and setup_tests; output only replaces BEGIN_LLM_REPLACE "
            "... END_LLM_REPLACE.\n"
        )
    if opts.task:
        out.append("\nScenario: {}\n".format(opts.task))

    out.append(_section("=== SOURCE_UNDER_TEST ({}) ===".format(src_rel)))
    src_text = _read(src_abs)
    if opts.full_source:
        out.append(src_text if src_text.endswith("\n") else src_text + "\n")
    else:
        total = len(src_text.splitlines())
        out.append(_head(src_text, opts.impl_lines) + "\n")
        if total > opts.impl_lines:
            out.append(
                "// ... truncated (total {} lines); use --full-source for "
                "entire file\n".format(total)
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
            "END_LLM_REPLACE in your stub (.c scaffold from the stub "
            "generator).\n"
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
