"""Turn Mull's surviving mutants into the text a prompt can carry.

Mull already says exactly which behaviours of a source file are unverified:
a surviving mutant is a change to the code that no test noticed. That list is
machine-generated, so a prompt built from it measures what the model can do
when told what to test, without a human first having to know the file well
enough to write the task by hand.

Two selections matter:

  survivors(report)      what one test failed to kill -- per-run diagnostics
  never_killed(reports)  what *no* recorded run has ever killed -- the target
                         set, and the thing an experiment is trying to move

Both are grouped into clusters by enclosing function, because that is the unit
a single test can plausibly address, and rendered against the source text so
the model sees the mutated line rather than a bare token and a line number.

Nothing here is specific to bio_enc.c: the function ranges come from the
source, the mutants from the report.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import paths, stub

# Mull counts a timeout as a kill, and so does mutation.py's score, so a
# mutant is "killed" here on exactly the same terms.
KILLED_STATUSES = frozenset({"Killed", "Timeout"})
# A mutant on a line the test never executed says nothing about the test's
# oracle -- it is a coverage fact. Tracked separately rather than merged in.
UNCOVERED_STATUS = "NotCovered"

# Mutants under paths a test can never be responsible for; mirrors mutation.py.
IGNORE_PREFIXES = ("/openssl/test/",)

# A top-level C function as OpenSSL writes one: a signature, then a brace
# alone in column 0, then a closing brace in column 0. Initialised aggregates
# ("static const BIO_METHOD methods_enc = {") end in "};" and are not matched.
_OPEN_BRACE_RE = re.compile(r"^\{\s*$")
_CLOSE_BRACE_RE = re.compile(r"^\}\s*$")
# The identifier immediately before the parameter list, in the last line of a
# possibly multi-line signature.
_NAME_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
# Where a signature cannot have started: the end of whatever came before it.
_BOUNDARY_RE = re.compile(r"(?:[;{}]|\*/)\s*$")


class MutantError(Exception):
    """A report could not be read, or a cluster could not be resolved."""


@dataclass(frozen=True)
class Mutant:
    """One mutation Mull applied, keyed the way Mull keys it."""

    id: str
    mutator: str
    replacement: str
    line: int
    column: int
    end_line: int
    end_column: int

    @property
    def sort_key(self) -> Tuple[int, int, str]:
        return (self.line, self.column, self.mutator)


@dataclass
class Cluster:
    """The surviving mutants of one enclosing function."""

    function: str
    start: int
    end: int
    mutants: List[Mutant] = field(default_factory=list)


@dataclass(frozen=True)
class Function:
    name: str
    start: int
    end: int


# --------------------------------------------------------------------------
# Source structure
# --------------------------------------------------------------------------

def find_functions(text: str) -> List[Function]:
    """Line ranges of the top-level functions in a C source file.

    Brace-matching a whole translation unit would need a parser; this only
    needs to answer "which function is line N in", and OpenSSL's style makes
    that a two-line pattern. A line outside every range is reported as such
    rather than guessed at.
    """
    lines = text.splitlines()
    out: List[Function] = []
    i = 0
    while i < len(lines):
        if not _OPEN_BRACE_RE.match(lines[i]):
            i += 1
            continue

        # Walk back over a signature that may span several lines.
        head = i - 1
        while head > 0 and not _BOUNDARY_RE.search(lines[head - 1]) and lines[head - 1].strip():
            head -= 1
        signature = " ".join(lines[head:i])
        names = _NAME_RE.findall(signature)
        if not names:
            i += 1
            continue

        end = i + 1
        while end < len(lines) and not _CLOSE_BRACE_RE.match(lines[end]):
            end += 1
        if end < len(lines):
            out.append(Function(names[-1], head + 1, end + 1))
        i = end + 1
    return out


def enclosing(functions: Sequence[Function], line: int) -> str:
    for fn in functions:
        if fn.start <= line <= fn.end:
            return fn.name
    return "(file scope)"


# --------------------------------------------------------------------------
# Reading reports
# --------------------------------------------------------------------------

def _mutant(raw: Dict) -> Mutant:
    start = (raw.get("location") or {}).get("start") or {}
    end = (raw.get("location") or {}).get("end") or {}
    return Mutant(
        id=raw.get("id") or "",
        mutator=raw.get("mutatorName") or "?",
        replacement=raw.get("replacement") or "",
        line=start.get("line") or 0,
        column=start.get("column") or 0,
        end_line=end.get("line") or start.get("line") or 0,
        end_column=end.get("column") or start.get("column") or 0,
    )


def _entry(report: Path, focus: str) -> Dict:
    """The report's record for the focus file, by container-path suffix."""
    try:
        data = json.loads(Path(report).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise MutantError("unreadable report {}: {}".format(report, exc))
    suffix = "/" + focus.lstrip("./")
    for path, entry in (data.get("files") or {}).items():
        if path.startswith(IGNORE_PREFIXES):
            continue
        if path.endswith(suffix):
            return entry
    return {}


def report_source(report: Path, focus: str) -> Optional[str]:
    """The source text Mull saw, which is what its line numbers refer to."""
    return (_entry(report, focus) or {}).get("source")


def survivors(report: Path, focus: str) -> List[Mutant]:
    """Mutants this one test run left alive."""
    return sorted(
        (_mutant(m) for m in (_entry(report, focus).get("mutants") or [])
         if m.get("status") == "Survived"),
        key=lambda m: m.sort_key,
    )


def never_killed(reports: Iterable[Path], focus: str) -> Tuple[List[Mutant], Dict[str, int]]:
    """Mutants no run in the corpus ever killed, with how many covered each.

    A mutant on a line most tests execute but none kill is an oracle problem;
    one nothing executes is a reachability problem. The coverage count is what
    tells those apart, so it comes back alongside.
    """
    seen: Dict[str, Mutant] = {}
    killed: Dict[str, int] = {}
    covered: Dict[str, int] = {}
    for report in reports:
        for raw in _entry(Path(report), focus).get("mutants") or []:
            mutant = _mutant(raw)
            key = mutant.id
            seen.setdefault(key, mutant)
            killed.setdefault(key, 0)
            covered.setdefault(key, 0)
            status = raw.get("status")
            if status in KILLED_STATUSES:
                killed[key] += 1
            if status != UNCOVERED_STATUS:
                covered[key] += 1
    alive = [m for key, m in seen.items() if killed[key] == 0]
    return sorted(alive, key=lambda m: m.sort_key), covered


def corpus_reports(records: Iterable[Dict]) -> Tuple[List[Path], List[str]]:
    """The Elements reports of every recorded run, and the runs missing one.

    "No run ever killed this mutant" is only as good as the set of reports it
    was computed over, and older records point at a results directory that has
    since been renamed. Those runs come back by name so the caller can say the
    denominator is short rather than quietly overstate the surviving set.
    """
    found, missing = [], []
    for record in records:
        if not record.get("ok"):
            continue
        report = record.get("report")
        path = paths.REPO_ROOT / report if report else None
        if path is not None and path.is_file():
            found.append(path)
        else:
            missing.append(record.get("name", "?"))
    return found, missing


# --------------------------------------------------------------------------
# Clustering and rendering
# --------------------------------------------------------------------------

def load_triage(path: Path) -> Dict[str, Dict]:
    """The hand classification of a file's surviving mutants, keyed by Mull id."""
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise MutantError("unreadable triage {}: {}".format(path, exc))
    return data.get("mutants") or {}


# What a triage entry can exclude a mutant for. "equivalent" is the bucket; the
# other two are flags on an otherwise ordinary mutant.
DROPPABLE = ("equivalent", "harness-blocked", "call-pattern")


def apply_triage(mutants: Sequence[Mutant], triage: Dict[str, Dict],
                 drop: Sequence[str] = ("equivalent",)) -> Tuple[List[Mutant], List[str]]:
    """Drop what a test cannot be scored against, and say what is unclassified.

    An equivalent mutant is unkillable by construction, so leaving it in the
    denominator records a model failure that is really a counting error -- and
    putting it in an Arm 2 prompt asks the model to kill something no test can,
    which is exactly the condition that manufactures a false hallucinated-
    coverage reading. "harness-blocked" and "call-pattern" are the same
    argument one step weaker: killable in principle, but not by a test written
    under this contract against this harness.

    A mutant the triage does not mention is kept and reported: the
    classification has to be redone when the corpus grows, and this says so.
    """
    unwanted = set(drop)
    kept, unknown = [], []
    for mutant in mutants:
        entry = triage.get(mutant.id)
        if entry is None:
            unknown.append(mutant.id)
            kept.append(mutant)
            continue
        flags = {entry.get("bucket")}
        if entry.get("harness_blocked"):
            flags.add("harness-blocked")
        if entry.get("call_pattern_only"):
            flags.add("call-pattern")
        if not (flags & unwanted):
            kept.append(mutant)
    return kept, unknown


def cluster(mutants: Sequence[Mutant], functions: Sequence[Function]) -> List[Cluster]:
    """Group mutants by enclosing function, biggest cluster first.

    The function is the unit a single test can plausibly address, and the
    grouping is mechanical -- line ranges from the source, mutants from the
    report -- so it carries over to any file.
    """
    ranges = {fn.name: fn for fn in functions}
    grouped: Dict[str, List[Mutant]] = {}
    for mutant in mutants:
        grouped.setdefault(enclosing(functions, mutant.line), []).append(mutant)

    out = []
    for name, members in grouped.items():
        fn = ranges.get(name)
        out.append(Cluster(
            function=name,
            start=fn.start if fn else min(m.line for m in members),
            end=fn.end if fn else max(m.line for m in members),
            mutants=sorted(members, key=lambda m: m.sort_key),
        ))
    return sorted(out, key=lambda c: (-len(c.mutants), c.start))


def _statement(lines: Sequence[str], index: int, span: int = 5) -> Tuple[str, List[int]]:
    """The line at `index` joined with its continuations, comments dropped.

    An assignment's right-hand side may run onto later lines, and it is the
    end of the *expression* that bounds the edit, so the text has to be
    searched as one string. The offsets where each joined line ends come back
    too, so the rendered result can be cut at the end of the line the
    expression actually finished on rather than trailing the whole join.
    """
    parts = [lines[index] if index < len(lines) else ""]
    for follow in lines[index + 1:index + span]:
        stripped = follow.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue
        parts.append(stripped)

    text, ends, at = "", [], 0
    for i, part in enumerate(parts):
        text += ("" if i == 0 else " ") + part
        at = len(text)
        ends.append(at)
    return text, ends


def _rhs_end(text: str, start: int, stops: str = ";,") -> int:
    """Where the expression beginning at `start` ends.

    That is the first `stops` character at the depth the expression started
    at, or the closing bracket that takes it below that depth -- which is what
    bounds an assignment used as a sub-expression, as in `if ((n = f(x)) == 0)`.
    Returns -1 if neither is found.
    """
    masked = stub.mask_c(text)
    depth = 0
    for i in range(start, len(masked)):
        ch = masked[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif depth == 0 and ch in stops:
            return i
    return -1


def _depth(text: str, upto: int) -> int:
    """Bracket depth at `upto`, so a ';' can be told from a for-header's ';'."""
    masked = stub.mask_c(text[:upto])
    return sum(masked.count(c) for c in "([{") - sum(masked.count(c) for c in ")]}")


def _tail(text: str, ends: Sequence[int], end: int, base: int) -> str:
    """What follows the expression, cut where the construct it sits in ends.

    A ';' outside every bracket closes the statement outright. Anywhere else
    it does not: inside `for (i = 0; ...)` it separates clauses, and inside
    `if ((n = f(x)) == 0)` the assignment was a sub-expression. In those cases
    the rest of that source line belongs in the rendering -- but nothing
    joined on after it does.
    """
    if base == 0 and text[end] == ";":
        return ";"
    stop = next((e for e in ends if e > end), len(text))
    return text[end:stop].rstrip()


def _assign_const(lines: Sequence[str], index: int, mutant: Mutant) -> Optional[str]:
    """`x = <expr>;` -> `x = 42;`, and `if ((x = f())...)` -> `if ((x = 42)...)`

    Mull points the location at the '=' alone, but its replacement stands in
    for the whole right-hand side. Splicing it over the operator would render
    `x = 42; <expr>;`, which is not the program Mull ran.
    """
    text, ends = _statement(lines, index)
    at = max(mutant.column - 1, 0)
    if at >= len(text):
        return None
    # Mull's replacement carries the ';' of the statement form; _tail supplies
    # the right terminator for either form.
    value = mutant.replacement.rstrip().rstrip(";").rstrip()
    end = _rhs_end(text, at + 1)
    if end < 0:
        return None
    return text[:at] + value + _tail(text, ends, end, _depth(text, at))


def _init_const(lines: Sequence[str], index: int, mutant: Mutant) -> Optional[str]:
    """`int x = <expr>, y;` -> `int x = 42, y;`

    Here the location is the declared name and the replacement is the new
    initialiser, so the span to overwrite is the initialiser that follows --
    not the identifier, which is what a literal splice would destroy.
    """
    text, ends = _statement(lines, index)
    name_end = max(mutant.end_column - 1, 0)
    if name_end >= len(text):
        return None
    end = _rhs_end(text, name_end)
    if end < 0:
        return None
    tail = _tail(text, ends, end, _depth(text, name_end))
    eq = stub.mask_c(text).find("=", name_end, end)
    if eq < 0:
        # A declarator with no initialiser: the mutant gives it one.
        return text[:end] + " = " + mutant.replacement + tail
    return text[:eq + 1] + " " + mutant.replacement + tail


# Mutators whose recorded span is the token Mull matched on rather than the
# region its replacement stands for. Everything else -- the binary-operator
# rewrites and cxx_remove_void_call -- splices literally.
SPAN_IS_NOT_THE_EDIT = {
    "cxx_assign_const": _assign_const,
    "cxx_init_const": _init_const,
}


def mutated_line(mutant: Mutant, lines: Sequence[str]) -> str:
    """The source line as the mutant leaves it.

    Mull's columns are 1-based with an exclusive end, so most replacements
    splice exactly. A model handed only "L160 cxx_le_to_lt" has to count lines
    and work out what the mutator does; handed the mutated line, it does not
    -- but only as long as the line shown is the one Mull actually ran, hence
    SPAN_IS_NOT_THE_EDIT.
    """
    if not (1 <= mutant.line <= len(lines)):
        return "?"
    line = lines[mutant.line - 1]
    if mutant.end_line != mutant.line:
        return line.strip() + "   [spans to line {}]".format(mutant.end_line)

    special = SPAN_IS_NOT_THE_EDIT.get(mutant.mutator)
    if special is not None:
        rendered = special(lines, mutant.line - 1, mutant)
        # Rather than show a line the mutant does not produce, say so: a wrong
        # rendering would mislead exactly the arm that depends on it.
        return rendered.strip() if rendered else "[{}, see line {}]".format(
            mutant.mutator, mutant.line)

    start = max(mutant.column - 1, 0)
    end = max(mutant.end_column - 1, start)
    return (line[:start] + mutant.replacement + line[end:]).strip()


def original_line(mutant: Mutant, lines: Sequence[str]) -> str:
    if not (1 <= mutant.line <= len(lines)):
        return "?"
    return lines[mutant.line - 1].strip()


def _rows(mutants: Sequence[Mutant], lines: Sequence[str]) -> List[Tuple[str, ...]]:
    rows = []
    for m in mutants:
        before = original_line(m, lines)
        after = ("removed" if m.replacement == ""
                 else mutated_line(m, lines))
        rows.append(("L{}".format(m.line), m.mutator, before, "->", after))
    return rows


def _aligned(rows: Sequence[Tuple[str, ...]], indent: str = "  ") -> str:
    if not rows:
        return ""
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    return "\n".join(
        indent + "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip()
        for row in rows
    )


BLOCK_HEADER = (
    "The following mutations were applied to {source} one at a\n"
    "time. Each produced a program that the existing test suite could not\n"
    "distinguish from the original: every test still passed.\n"
)

BLOCK_FOOTER = (
    "Write a test that FAILS when any one of these mutations is applied and\n"
    "PASSES on the unmodified source. The test must set up whatever input\n"
    "conditions are required to make each mutation observable.\n"
)


def format_block(mutants: Sequence[Mutant], source_text: str, source_rel: str) -> str:
    """The mutant-directed task string: what survived, and what to do about it."""
    lines = source_text.splitlines()
    return "{}\n{}\n\n{}".format(
        BLOCK_HEADER.format(source=source_rel),
        _aligned(_rows(mutants, lines)),
        BLOCK_FOOTER,
    )


def format_table(clusters: Sequence[Cluster], source_text: str,
                 covered: Optional[Dict[str, int]] = None,
                 runs: Optional[int] = None) -> str:
    """The triage view: one row per mutant, grouped, with its coverage count.

    This is what the equivalent-mutant pass is done against, so it shows the
    original line as well as the mutated one -- the classification is a
    judgement about the code, not about the mutator's name.
    """
    lines = source_text.splitlines()
    out: List[str] = []
    total = 0
    for group in clusters:
        out.append("{} (lines {}-{}) -- {} mutant(s)".format(
            group.function, group.start, group.end, len(group.mutants)))
        rows = []
        for m in group.mutants:
            cov = "" if covered is None else "cov={}{}".format(
                covered.get(m.id, 0), "/{}".format(runs) if runs else "")
            rows.append(("L{}".format(m.line), m.mutator, cov,
                         original_line(m, lines), "->",
                         "removed" if m.replacement == "" else mutated_line(m, lines)))
        out.append(_aligned(rows, indent="    "))
        out.append("")
        total += len(group.mutants)
    out.append("{} mutant(s) in {} cluster(s)".format(total, len(clusters)))
    return "\n".join(out)


def to_json(clusters: Sequence[Cluster], source_text: str,
            covered: Optional[Dict[str, int]] = None) -> str:
    lines = source_text.splitlines()
    payload = [
        {
            "function": group.function,
            "start": group.start,
            "end": group.end,
            "mutants": [
                {
                    "id": m.id,
                    "line": m.line,
                    "column": m.column,
                    "mutator": m.mutator,
                    "replacement": m.replacement,
                    "original": original_line(m, lines),
                    "mutated": mutated_line(m, lines),
                    "covered_by": None if covered is None else covered.get(m.id, 0),
                }
                for m in group.mutants
            ],
        }
        for group in clusters
    ]
    return json.dumps(payload, indent=2) + "\n"
