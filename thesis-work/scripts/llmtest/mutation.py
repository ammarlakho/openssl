"""Run Mull over generated tests and keep the numbers, not the scrollback.

Mull's default output is a wall of file:line warnings. It also speaks the
Mutation Testing Elements schema, which is one JSON object per run listing
every mutant with its mutator, location and status. mull.sh now always asks
for it, so each run leaves:

    thesis-work/experiments/results/<name>/<name>.json  every mutant, machine readable
    thesis-work/experiments/results/<name>/<name>.txt   the usual warnings, for reading
    thesis-work/experiments/results/<name>/run.json     what this module made of it
    thesis-work/experiments/results/results.jsonl       one line per run, ever
    thesis-work/experiments/results/results.csv         the same, flat, for plotting

The per-run directories are gitignored -- they are logs and Mull's full report,
tens of MB a night. The two results files are the committed record.

A test only mutation-scores well on the code it actually exercises, so every
summary is reported twice: over the whole tree, and restricted to the source
under test ("focus"), which is the number an experiment is really asking about.
"""

import csv
import json
import os
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import experiment, paths

MUTATION_DIR = paths.RESULTS_DIR
RESULTS = paths.RESULTS_JSONL
RESULTS_CSV = paths.RESULTS_CSV
MULL_SH = paths.THESIS_ROOT / "mull-mutation" / "mull.sh"

# The CSV is append-only and outlives any one experiment, so its header cannot
# depend on which grid axes today's config happens to vary: every known axis
# gets a column, blank when unused. Add axes to experiment.AXES, not here.
CSV_COLUMNS = (
    ["name", "run_utc", "ok", "model", "source"]
    + list(experiment.AXES)
    # The bare names are the overall numbers, which are the headline; the focus
    # ones keep their prefix.
    + ["score", "mutants", "killed", "survived", "not_covered", "timeout",
       "focus_score", "focus_mutants", "focus_killed", "focus_survived",
       "duration_s", "error"]
)

# Mull reports these; anything else is a schema surprise worth seeing.
STATUSES = ("Killed", "Survived", "NotCovered", "Timeout", "Crashed", "CompileError")

# Mutants under paths the test can never be responsible for would only dilute
# the score. Kept deliberately short: the focus view is the real filter.
IGNORE_PREFIXES = ("/openssl/test/",)


class MutationError(Exception):
    """A mutation run could not be started, or its report could not be read."""


def log(message: str) -> None:
    print(message, flush=True)


# --------------------------------------------------------------------------
# Reading a report
# --------------------------------------------------------------------------

def _score(counts: Dict[str, int]) -> Optional[float]:
    """Killed / (Killed + Survived + Timeout), as a percentage.

    Timeouts count as killed the way Mull counts them; NotCovered mutants are
    excluded, since not running a line is a coverage fact, not a test failure.
    """
    killed = counts.get("Killed", 0) + counts.get("Timeout", 0)
    total = killed + counts.get("Survived", 0)
    return round(100.0 * killed / total, 2) if total else None


def _tally(mutants: List[Dict[str, Any]]) -> Dict[str, Any]:
    status = Counter(m.get("status", "?") for m in mutants)
    survived = Counter(
        m.get("mutatorName", "?") for m in mutants if m.get("status") == "Survived")
    return {
        "mutants": len(mutants),
        "score": _score(status),
        "status": {k: status[k] for k in sorted(status)},
        "survived_by_mutator": {k: survived[k] for k in sorted(survived)},
    }


def summarise(report: Path, focus: Optional[str] = None) -> Dict[str, Any]:
    """Turn one Elements report into the counts an experiment cares about.

    `focus` is a repo-relative source path (e.g. crypto/evp/bio_enc.c); the
    report keys paths as they were seen inside the container.
    """
    try:
        data = json.loads(Path(report).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise MutationError("unreadable report {}: {}".format(report, exc))

    overall: List[Dict[str, Any]] = []
    focused: List[Dict[str, Any]] = []
    per_file: Dict[str, int] = {}
    suffix = "/" + focus.lstrip("./") if focus else None

    for path, entry in (data.get("files") or {}).items():
        mutants = entry.get("mutants") or []
        if path.startswith(IGNORE_PREFIXES):
            continue
        overall.extend(mutants)
        per_file[path] = len(mutants)
        if suffix and path.endswith(suffix):
            focused.extend(mutants)

    result = {
        "mull_version": (data.get("config") or {}).get("Mull Version"),
        "mull_score": data.get("mutationScore"),   # Mull's own, over every file
        "files": len(per_file),
        "overall": _tally(overall),
    }
    if suffix:
        result["focus"] = focus
        result["focus_stats"] = _tally(focused)
        if not focused:
            result["focus_stats"]["note"] = "no mutants reported in this file"
    return result


def surviving_lines(report: Path, focus: Optional[str] = None) -> List[Dict[str, Any]]:
    """Every surviving mutant, so a run can be inspected without rerunning it."""
    data = json.loads(Path(report).read_text())
    suffix = "/" + focus.lstrip("./") if focus else None
    out = []
    for path, entry in (data.get("files") or {}).items():
        if path.startswith(IGNORE_PREFIXES):
            continue
        if suffix and not path.endswith(suffix):
            continue
        for mutant in entry.get("mutants") or []:
            if mutant.get("status") != "Survived":
                continue
            out.append({
                "file": path,
                "line": (mutant.get("location") or {}).get("start", {}).get("line"),
                "mutator": mutant.get("mutatorName"),
                "replacement": mutant.get("replacement"),
            })
    return sorted(out, key=lambda m: (m["file"], m["line"] or 0))


# --------------------------------------------------------------------------
# Running
# --------------------------------------------------------------------------

def _mull(args: List[str], report_dir: Path, name: str, log_file: Path):
    """Run mull.sh, tee-ing its noise to a file instead of the terminal."""
    env = dict(os.environ)
    env["MULL_REPORT_DIR"] = str(report_dir.relative_to(paths.REPO_ROOT))
    env["MULL_REPORT_NAME"] = name
    with log_file.open("a") as handle:
        return subprocess.run(
            [str(MULL_SH)] + args,
            cwd=str(paths.REPO_ROOT), env=env,
            stdout=handle, stderr=subprocess.STDOUT,
        )


def _tail(path: Path, lines: int = 12) -> str:
    try:
        return "\n".join(path.read_text(errors="replace").splitlines()[-lines:])
    except OSError:
        return ""


def run_one(name: str, source: Optional[str] = None, build: bool = True,
            params: Optional[Dict[str, Any]] = None,
            model: Optional[str] = None) -> Dict[str, Any]:
    """Build (optionally) and mutate test/<name>, returning its record."""
    binary = "./test/{}".format(name)
    report_dir = MUTATION_DIR / name
    report_dir.mkdir(parents=True, exist_ok=True)
    build_log = report_dir / "build.log"
    mutate_log = report_dir / "mull.log"
    for stale in (build_log, mutate_log):
        stale.unlink(missing_ok=True)

    record: Dict[str, Any] = {
        "name": name,
        "binary": binary,
        "source": source,
        "model": model,
        "params": params or {},
        "run_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ok": False,
        "stage": None,
        "error": None,
        "duration_s": None,
    }
    started = time.monotonic()

    if build:
        done = _mull(["build-test", binary], report_dir, name, build_log)
        if done.returncode != 0:
            record.update(stage="build", error="build failed; see {}".format(build_log),
                          log_tail=_tail(build_log))
            record["duration_s"] = round(time.monotonic() - started, 1)
            return record
        if not (paths.TEST_DIR / name).is_file():
            record.update(stage="build", error="no binary at {}".format(binary),
                          log_tail=_tail(build_log))
            record["duration_s"] = round(time.monotonic() - started, 1)
            return record

    done = _mull(["mutate", binary], report_dir, name, mutate_log)
    report = report_dir / "{}.json".format(name)
    if done.returncode != 0 or not report.is_file():
        record.update(stage="mutate",
                      error="mull failed (exit {}); see {}".format(done.returncode, mutate_log),
                      log_tail=_tail(mutate_log))
        record["duration_s"] = round(time.monotonic() - started, 1)
        return record

    record["report"] = str(report.relative_to(paths.REPO_ROOT))
    record.update(summarise(report, source))
    record["ok"] = True
    record["duration_s"] = round(time.monotonic() - started, 1)
    (report_dir / "run.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


def _targets(names: List[str], all_runs: bool, out_dir: Optional[str],
             source: Optional[str] = None) -> List[Dict[str, Any]]:
    """Resolve names to (name, source, params), preferring what the experiment recorded.

    A test written by hand has no run directory and so no recorded source; the
    focus view is what an experiment is really asking about, so rather than
    silently dropping it, `source` stands in for those.
    """
    runs = {r["name"]: r for r in experiment.list_runs(out_dir) if r.get("ok")}
    if all_runs:
        chosen = sorted(runs)
    else:
        chosen = names
    targets = []
    for name in chosen:
        meta = runs.get(name, {})
        if not all_runs and name not in runs and not (paths.TEST_DIR / "{}.c".format(name)).is_file():
            raise MutationError("no generated run or test source named {}".format(name))
        focus = meta.get("source") or source
        if focus and not meta.get("source"):
            log(">> [Mutation] {}: no recorded source; focusing on {}".format(name, focus))
        targets.append({
            "name": name,
            "source": focus,
            "model": meta.get("model"),
            "params": meta.get("params") or {},
        })
    if not targets:
        raise MutationError("nothing to mutate")
    return targets


# What a --rerun mode is willing to run again. A test file never changes once
# generated and mutation is deterministic, so by default a name that already
# has a record -- of either kind -- is left alone.
RERUN_MODES = {
    "none": (),                         # only names never run before
    "failed": ("failed",),              # + retry the ones that failed
    "scored": ("scored",),              # + re-measure the ones that succeeded
    "all": ("failed", "scored"),        # everything asked for
}


def recorded() -> Dict[str, bool]:
    """name -> did its most recent run succeed."""
    return {r["name"]: bool(r.get("ok")) for r in load_results(latest_only=True)}


def run_batch(names: List[str], all_runs: bool = False, out_dir: Optional[str] = None,
              configure: bool = True, build: bool = True,
              rerun: str = "none", source: Optional[str] = None) -> List[Dict[str, Any]]:
    """Mutate several tests. The coverage reconfigure is shared across them.

    See RERUN_MODES for which already-recorded tests are run again; the rest
    are skipped, so repeating `mutate --all` after adding a few generated tests
    costs only those few.
    """
    if rerun not in RERUN_MODES:
        raise MutationError("unknown --rerun mode: {}".format(rerun))
    targets = _targets(names, all_runs, out_dir, source)
    MUTATION_DIR.mkdir(parents=True, exist_ok=True)

    allowed = RERUN_MODES[rerun]
    before = recorded()

    def skip_reason(name: str) -> Optional[str]:
        if name not in before:
            return None
        kind = "scored" if before[name] else "failed"
        return None if kind in allowed else kind

    skipped = [(t["name"], skip_reason(t["name"])) for t in targets]
    skipped = [(n, why) for n, why in skipped if why]
    targets = [t for t in targets if not skip_reason(t["name"])]

    if skipped:
        log(">> [Mutation] skipping {} already recorded (--rerun {}):".format(
            len(skipped), "|".join(sorted(RERUN_MODES))))
        for name, why in skipped:
            log(">> [Mutation]   {:<8} {}".format(why, name))
    if not targets:
        log(">> [Mutation] nothing left to do; see `mutation-report`")
        return []

    if configure:
        log(">> [Mutation] configuring the tree for coverage (once)")
        setup_log = MUTATION_DIR / "configure.log"
        setup_log.unlink(missing_ok=True)
        done = _mull(["configure-cov"], MUTATION_DIR, "configure", setup_log)
        if done.returncode != 0:
            raise MutationError("configure-cov failed; see {}\n{}".format(
                setup_log, _tail(setup_log)))

    results = []
    for i, target in enumerate(targets, 1):
        log(">> [Mutation] ({}/{}) {}".format(i, len(targets), target["name"]))
        record = run_one(target["name"], target["source"], build=build,
                         params=target["params"], model=target["model"])
        results.append(record)
        _append(record)

        if record["ok"]:
            overall = record["overall"]
            focus = record.get("focus_stats") or {}
            log(">> [Mutation] {} score={} ({} mutants, {} survived)"
                " focus={} ({}) in {}s".format(
                    target["name"], overall["score"], overall["mutants"],
                    overall["status"].get("Survived", 0),
                    focus.get("score", "-"), focus.get("mutants", "-"),
                    record["duration_s"]))
        else:
            log(">> [Mutation] FAILED {} at {}: {}".format(
                target["name"], record["stage"], record["error"]))
    return results


def _append(record: Dict[str, Any]) -> None:
    """Both records grow as the batch runs, so an interrupted batch keeps what it did."""
    MUTATION_DIR.mkdir(parents=True, exist_ok=True)
    with RESULTS.open("a") as handle:
        handle.write(json.dumps(record) + "\n")
    append_csv([record])


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def load_results(latest_only: bool = True) -> List[Dict[str, Any]]:
    """Every recorded run; by default only the newest per test name."""
    if not RESULTS.is_file():
        return []
    records = []
    for line in RESULTS.read_text().splitlines():
        if line.strip():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if not latest_only:
        return records
    newest: Dict[str, Dict[str, Any]] = {}
    for record in records:          # the file is append-only, so last wins
        newest[record["name"]] = record
    return [newest[k] for k in sorted(newest)]


def _pct(value: Optional[float]) -> str:
    return "-" if value is None else "{:.1f}".format(value)


def table(records: List[Dict[str, Any]]) -> str:
    """A fixed-width summary: overall first, focus alongside it."""
    row = "{:<48} {:>7} {:>8} {:>7} {:>8} {:>7} {:>7} {:>6}"
    header = row.format("test", "score%", "mutants", "killed", "survived",
                        "focus%", "f_mut", "time")
    rows = [header, "-" * len(header)]
    for record in records:
        if not record.get("ok"):
            rows.append("{:<48} {:>7}  {}".format(
                record["name"][:48], "FAIL", record.get("error", "")[:44]))
            continue
        overall = record["overall"]
        focus = record.get("focus_stats") or {}
        rows.append(row.format(
            record["name"][:48],
            _pct(overall["score"]),
            overall["mutants"],
            overall["status"].get("Killed", 0) + overall["status"].get("Timeout", 0),
            overall["status"].get("Survived", 0),
            _pct(focus.get("score")),
            focus.get("mutants", "-"),
            "{}s".format(record.get("duration_s") or "?")))
    return "\n".join(rows)


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return "{:.2f}".format(value)
    return str(value)


def csv_row(record: Dict[str, Any]) -> List[str]:
    """One record as CSV_COLUMNS: the overall numbers, then the focus ones."""
    overall = record.get("overall") or {}
    status = overall.get("status") or {}
    focus = record.get("focus_stats") or {}
    focus_status = focus.get("status") or {}
    params = record.get("params") or {}

    values: Dict[str, Any] = {
        "name": record.get("name"),
        "run_utc": record.get("run_utc"),
        "ok": 1 if record.get("ok") else 0,
        "model": record.get("model"),
        "source": record.get("source"),
        "score": overall.get("score"),
        "mutants": overall.get("mutants"),
        "killed": status.get("Killed", 0) + status.get("Timeout", 0),
        "survived": status.get("Survived", 0),
        "not_covered": status.get("NotCovered", 0),
        "timeout": status.get("Timeout", 0),
        "focus_score": focus.get("score"),
        "focus_mutants": focus.get("mutants"),
        "focus_killed": focus_status.get("Killed", 0) + focus_status.get("Timeout", 0),
        "focus_survived": focus_status.get("Survived", 0),
        "duration_s": record.get("duration_s"),
        "error": record.get("error"),
    }
    values.update({axis: params.get(axis) for axis in experiment.AXES})
    if not record.get("ok") or not focus:
        for key in ("focus_score", "focus_mutants", "focus_killed", "focus_survived"):
            values[key] = None
    if not record.get("ok"):
        # A failed run has no numbers; empty cells beat zeros that plot.
        for key in ("score", "mutants", "killed", "survived", "not_covered",
                    "timeout"):
            values[key] = None
    return [_cell(values.get(column)) for column in CSV_COLUMNS]


def append_csv(records: List[Dict[str, Any]], path: Optional[Path] = None) -> Path:
    """Append rows to the running CSV, writing the header only when creating it."""
    path = Path(path) if path else RESULTS_CSV
    path.parent.mkdir(parents=True, exist_ok=True)
    fresh = not path.is_file() or path.stat().st_size == 0
    with path.open("a", newline="") as handle:
        writer = csv.writer(handle)
        if fresh:
            writer.writerow(CSV_COLUMNS)
        for record in records:
            writer.writerow(csv_row(record))
    return path


def rebuild_csv(path: Optional[Path] = None) -> Path:
    """Regenerate the CSV from results.jsonl, which is the source of truth.

    For picking up runs recorded before the CSV existed, or after editing the
    columns. One row per test name -- the newest run wins, so a name remutated
    after a fix appears once, with the score that still holds.
    """
    path = Path(path) if path else RESULTS_CSV
    if path.is_file():
        path.unlink()
    return append_csv(load_results(latest_only=True), path)
