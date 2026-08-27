"""Run a grid of generation parameters and save each result as its own test.

One run = one (temperature, top_p, seed, penalty, ...) combination:

    test/<name>.c               the filled stub, flat with every other test
    test/generated/<name>/      meta.json, prompt.txt, response.txt
    test/generated/runs.jsonl   one line per run

The .c stays in test/ because a test's `#include "testutil.h"` resolves
relative to its own directory, which build.info's INCLUDE cannot override.

<name> encodes the model, the knobs and a timestamp. Successful runs are
registered in test/build.info, giving a binary at test/<name>.

The grid comes from a JSON config, so re-running with different parameters is a
config edit; --grid overrides individual axes from the command line.
"""

import hashlib
import itertools
import json
import shutil
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import backends, buildinfo, paths, stub
from .backends import BackendError, GenParams
from .context import GENERATED_MARKER, ContextOptions, build_prompt

# Everything an experiment produces lives here, one directory per run.
OUT_DIR = paths.TEST_DIR / "generated"
INDEX = OUT_DIR / "runs.jsonl"

# Axes that may appear in "grid". Each maps to a GenParams field and to the
# short tag used in a run's name.
AXES = {
    "temperature": "t",
    "top_p": "tp",
    "frequency_penalty": "fp",
    "presence_penalty": "pp",
    "repetition_penalty": "rp",
    "seed": "s",
    "max_tokens": "mt",
    "reasoning_effort": "re",
}

# Grid values arrive from JSON, so the axis decides the type.
AXIS_TYPES = {
    "temperature": float,
    "top_p": float,
    "frequency_penalty": float,
    "presence_penalty": float,
    "repetition_penalty": float,
    "seed": int,
    "max_tokens": int,
    "reasoning_effort": str,
}

DEFAULT_CONFIG: Dict[str, Any] = {
    "source": "crypto/evp/bio_enc.c",
    "task": "AES-256 CBC BIO round-trip vs fixed vectors",
    "test_fn": None,          # default: derived from the source stem
    "prefix": "gen",          # leading component of every run name
    "profile": None,          # None: whatever llm-models.env says
    "model": None,
    "api_url": None,
    "snippet": True,
    "repeats": 1,             # runs per grid point
    "sleep": 0.0,             # seconds between calls, to be kind to the server
    "context": {},            # ContextOptions knobs: refs, lines, keywords, ...
    "grid": {"temperature": [0.2, 0.8], "seed": [1, 2, 3]},
}


class ExperimentError(Exception):
    """An experiment could not be planned or run."""


# --------------------------------------------------------------------------
# Naming
# --------------------------------------------------------------------------

def _slug(text: str, limit: int = 20) -> str:
    """Lowercase [a-z0-9_] only: run names become make targets and C filenames."""
    out = []
    for ch in text.lower():
        out.append(ch if ch.isalnum() else "_")
    slug = "".join(out).strip("_")
    while "__" in slug:
        slug = slug.replace("__", "_")
    return slug[:limit].strip("_")


def _num(value: Any) -> str:
    """0.8 -> 0p8, 1.05 -> 1p05, 7 -> 7. '.' is illegal in a make target."""
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, float):
        text = ("%g" % value)
    else:
        text = str(value)
    return _slug(text.replace(".", "p"), limit=8)


def run_name(prefix: str, model: str, point: Dict[str, Any], stamp: str,
             repeat: Optional[int] = None) -> str:
    """A name that says which model and which knobs produced this test."""
    bits = [_slug(prefix, 12), _slug(model.split("/")[-1], 20)]
    for axis, tag in AXES.items():
        if axis in point and point[axis] is not None:
            bits.append("{}{}".format(tag, _num(point[axis])))
    if repeat is not None:
        bits.append("r{}".format(repeat))
    bits.append(stamp)
    return "_".join(b for b in bits if b)


# --------------------------------------------------------------------------
# Config and grid
# --------------------------------------------------------------------------

def load_config(path: Optional[str]) -> Dict[str, Any]:
    config = dict(DEFAULT_CONFIG)
    if path:
        cfg_path = Path(path)
        if not cfg_path.is_file():
            cfg_path = paths.resolve_under_repo(path)
        if not cfg_path.is_file():
            raise ExperimentError("config not found: {}".format(path))
        try:
            loaded = json.loads(cfg_path.read_text())
        except json.JSONDecodeError as exc:
            raise ExperimentError("{}: {}".format(cfg_path, exc))
        unknown = set(loaded) - set(DEFAULT_CONFIG)
        if unknown:
            raise ExperimentError("unknown config keys: {}".format(", ".join(sorted(unknown))))
        config.update(loaded)
    return config


def parse_grid_override(entries: List[str]) -> Dict[str, List[Any]]:
    """--grid temperature=0.2,0.8 --grid seed=1,2,3 -> {"temperature": [...]}"""
    grid: Dict[str, List[Any]] = {}
    for entry in entries or []:
        axis, _, values = entry.partition("=")
        axis = axis.strip()
        if not values.strip():
            raise ExperimentError("--grid needs axis=v1,v2 (got {!r})".format(entry))
        grid[axis] = [v.strip() for v in values.split(",") if v.strip()]
    return grid


def normalise_grid(grid: Dict[str, Any]) -> Dict[str, List[Any]]:
    clean: Dict[str, List[Any]] = {}
    for axis, values in grid.items():
        if axis not in AXES:
            raise ExperimentError(
                "unknown grid axis {!r}; known axes: {}".format(
                    axis, ", ".join(sorted(AXES))))
        if not isinstance(values, (list, tuple)):
            values = [values]
        cast = AXIS_TYPES[axis]
        try:
            clean[axis] = [None if v is None else cast(v) for v in values]
        except (TypeError, ValueError) as exc:
            raise ExperimentError("bad value on axis {}: {}".format(axis, exc))
        if not clean[axis]:
            raise ExperimentError("axis {} has no values".format(axis))
    return clean


def expand_grid(grid: Dict[str, List[Any]]) -> List[Dict[str, Any]]:
    """Cartesian product, in config order, so the plan reads predictably."""
    if not grid:
        return [{}]
    axes = list(grid)
    return [dict(zip(axes, combo)) for combo in itertools.product(*(grid[a] for a in axes))]


# --------------------------------------------------------------------------
# Running
# --------------------------------------------------------------------------

def _default_test_fn(source: str) -> str:
    return "test_{}_generated".format(_slug(Path(source).stem, 40))


def _context_options(config: Dict[str, Any], stub_path: Path) -> ContextOptions:
    ctx = dict(config.get("context") or {})
    unknown = set(ctx) - {"notes", "keywords", "impl_lines", "refs", "lines"}
    if unknown:
        raise ExperimentError("unknown context keys: {}".format(", ".join(sorted(unknown))))
    return ContextOptions(
        snippet=bool(config["snippet"]),
        notes=bool(ctx.get("notes", False)),
        task=config.get("task") or "",
        keywords=list(ctx.get("keywords") or []),
        impl_lines=ctx.get("impl_lines"),
        refs=ctx.get("refs"),
        lines=ctx.get("lines"),
        stub_path=str(stub_path) if config["snippet"] else None,
    )


def _out_root(out_dir) -> Path:
    """Resolve --out-dir the way every other path argument resolves: against the
    repo root, so it means the same thing from any cwd."""
    return paths.resolve_under_repo(str(out_dir)) if out_dir else OUT_DIR


def _rel(path: Path) -> str:
    """Repo-relative where possible; absolute for an --out-dir outside the tree."""
    try:
        return str(path.relative_to(paths.REPO_ROOT))
    except ValueError:
        return str(path)


def _taken(out_root: Path, name: str) -> bool:
    return (out_root / name).exists() or (paths.TEST_DIR / "{}.c".format(name)).exists()


def _unique_dir(base: Path) -> Path:
    out_root, name = base.parent, base.name
    if not _taken(out_root, name):
        return base
    for n in itertools.count(2):
        candidate = "{}_{}".format(name, n)
        if not _taken(out_root, candidate):
            return out_root / candidate


def plan(config: Dict[str, Any], grid_override: Dict[str, List[Any]]) -> List[Dict[str, Any]]:
    """Every run this experiment will perform, before any of them happen."""
    grid = dict(config.get("grid") or {})
    grid.update(grid_override)
    points = expand_grid(normalise_grid(grid))

    repeats = int(config.get("repeats") or 1)
    if repeats < 1:
        raise ExperimentError("repeats must be >= 1")

    runs = []
    for point in points:
        for r in range(1, repeats + 1):
            runs.append({"point": point, "repeat": r if repeats > 1 else None})
    return runs


def _check_axes(endpoint, runs: List[Dict[str, Any]]) -> None:
    """Refuse to sweep an axis the chosen backend cannot apply.

    The Claude CLI has no temperature, top_p or seed. Sweeping them there would
    still produce runs -- named `..._t0p2_s3`, recorded with those params in
    meta.json -- but every one of them would be the backend's default decoding,
    so the results would compare settings that were never sent. Better to stop
    before the first call than to record a sweep that did not happen.
    """
    swept = {axis for run in runs for axis in run["point"]}
    bad = sorted(swept & set(endpoint.unsupported))
    if bad:
        raise ExperimentError(
            "profile '{}' ({} backend) cannot vary {}. Drop {} from the grid; "
            "use \"repeats\" for run-to-run variance, and \"reasoning_effort\" "
            "for the one knob this backend does have.".format(
                endpoint.profile, endpoint.kind, ", ".join(bad),
                "it" if len(bad) == 1 else "them"))


def run_experiment(
    config: Dict[str, Any],
    grid_override: Optional[Dict[str, List[Any]]] = None,
    dry_run: bool = False,
    limit: Optional[int] = None,
    register: bool = True,
    out_dir: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    runs = plan(config, grid_override or {})
    if limit is not None:
        runs = runs[:limit]

    out_root = _out_root(out_dir)
    source = config["source"]
    test_fn = config.get("test_fn") or _default_test_fn(source)
    source_path = paths.resolve_under_repo(source)
    if not source_path.is_file():
        raise ExperimentError("source under test not found: {}".format(source_path))

    endpoint = backends.resolve_profile(
        config.get("profile"), config.get("api_url"), config.get("model"))
    _check_axes(endpoint, runs)

    backends.log(">> [Experiment] {} run(s) | profile={} {} | out={}".format(
        len(runs), endpoint.profile, endpoint.describe(), out_root))

    results = []
    for i, run in enumerate(runs, 1):
        point = run["point"]
        stamp = datetime.now().strftime("%y%m%d_%H%M%S")
        name = run_name(config.get("prefix") or "gen", endpoint.model, point, stamp,
                        run["repeat"])

        backends.log(">> [Experiment] ({}/{}) {} [{}]".format(
            i, len(runs), name,
            ", ".join("{}={}".format(k, v) for k, v in sorted(point.items())) or "server defaults"))

        record = {
            "name": name,
            "index": i,
            "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "profile": endpoint.profile,
            "backend": endpoint.kind,
            "api_url": endpoint.api_url,
            "model": endpoint.model,
            "params": point,
            "source": source,
            "task": config.get("task") or "",
            "test_fn": test_fn,
            "snippet": bool(config["snippet"]),
            "context": config.get("context") or {},
            "ok": False,
            "error": None,
            "duration_s": None,
        }

        if dry_run:
            record["dry_run"] = True
            record["dir"] = _rel(out_root / name)
            results.append(record)
            continue

        run_dir = _unique_dir(out_root / name)
        name = run_dir.name
        record["name"] = name
        run_dir.mkdir(parents=True)

        test_c = paths.TEST_DIR / "{}.c".format(name)
        test_c.write_text(stub.generate_stub(name, test_fn, source_path))
        record["dir"] = _rel(run_dir)
        record["source_file"] = str(test_c.relative_to(paths.REPO_ROOT))
        record["binary"] = "test/{}".format(name)

        started = time.monotonic()
        try:
            prompt = build_prompt(source, _context_options(config, test_c))
            (run_dir / "prompt.txt").write_text(prompt)
            record["prompt_sha256"] = hashlib.sha256(prompt.encode()).hexdigest()[:16]

            params = GenParams(**point)
            reply = backends.run_prompt(prompt, endpoint, params)
            (run_dir / "response.txt").write_text(reply)
            stub.fill_stub(test_c, reply)
            record["ok"] = True
        except Exception as exc:                       # noqa: BLE001
            record["error"] = "{}: {}".format(type(exc).__name__, exc)
            backends.log(">> [Experiment] FAILED {}: {}".format(name, record["error"]))
        record["duration_s"] = round(time.monotonic() - started, 1)

        if record["ok"] and register:
            rel_source = str(test_c.relative_to(paths.TEST_DIR))
            buildinfo.register(name, rel_source)
            record["registered"] = True
            backends.log(">> [Experiment] registered {} (SOURCE={})".format(name, rel_source))

        (run_dir / "meta.json").write_text(json.dumps(record, indent=2) + "\n")
        _append_index(out_root, record)
        results.append(record)

        delay = float(config.get("sleep") or 0)
        if delay and i < len(runs):
            time.sleep(delay)

    ok = sum(1 for r in results if r.get("ok"))
    if not dry_run:
        backends.log(">> [Experiment] done: {}/{} succeeded; index: {}".format(
            ok, len(results), (out_root / INDEX.name)))
        for record in results:
            if record.get("ok"):
                backends.log(">> [Experiment] ./thesis-work/mull-mutation/mull.sh run-cov ./{}".format(
                    record["binary"]))
    return results


def _append_index(out_root: Path, record: Dict[str, Any]) -> None:
    out_root.mkdir(parents=True, exist_ok=True)
    with (out_root / INDEX.name).open("a") as handle:
        handle.write(json.dumps(record) + "\n")


# --------------------------------------------------------------------------
# Pruning
# --------------------------------------------------------------------------

def list_runs(out_root: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Every run present on disk, newest name last."""
    out_root = _out_root(out_root)
    if not out_root.is_dir():
        return []

    runs = []
    for run_dir in sorted(p for p in out_root.iterdir() if p.is_dir()):
        meta_file = run_dir / "meta.json"
        try:
            meta = json.loads(meta_file.read_text()) if meta_file.is_file() else {}
        except json.JSONDecodeError:
            meta = {}
        meta.setdefault("name", run_dir.name)
        # No meta.json: interrupted, or files removed by hand -- not the same
        # as a run that failed.
        meta["_incomplete"] = not meta_file.is_file()
        meta["_dir"] = run_dir
        runs.append(meta)
    return runs


def select_runs(names: List[str], all_runs: bool, failed_only: bool,
                out_root: Optional[Path] = None) -> List[Dict[str, Any]]:
    runs = list_runs(out_root)
    if all_runs:
        chosen = runs
    elif failed_only:
        chosen = [r for r in runs if not r.get("ok")]
    else:
        by_name = {r["name"]: r for r in runs}
        chosen = []
        for name in names:
            if name not in by_name:
                raise ExperimentError("no such run under {}: {}".format(
                    out_root or OUT_DIR, name))
            chosen.append(by_name[name])
    return chosen


def prune(names: List[str], all_runs: bool = False, failed_only: bool = False,
          dry_run: bool = False, keep_index: bool = False,
          out_root: Optional[Path] = None) -> List[str]:
    """Delete runs: test/<name>.c, the run directory, the build.info entries.

    Only runs recorded under the experiment output directory are touched, and only a
    .c still carrying the stub's LLM_REPLACE markers is deleted, so a
    hand-written test can never be removed by a name collision here.
    """
    out_root = _out_root(out_root)
    chosen = select_runs(names, all_runs, failed_only, out_root)
    if not chosen:
        backends.log(">> [Prune] nothing to delete")
        return []

    removed = []
    for run in chosen:
        name = run["name"]
        run_dir = run["_dir"]
        test_c = paths.REPO_ROOT / run.get("source_file", "test/{}.c".format(name))
        drop_c = test_c.is_file() and GENERATED_MARKER in test_c.read_text(errors="replace")
        registered = buildinfo.source_of(name)

        targets = [str(run_dir)]
        if drop_c:
            targets.append(str(test_c))
        if registered:
            targets.append("build.info entry")

        if dry_run:
            backends.log(">> [Prune] would delete {}".format(", ".join(targets)))
            removed.append(name)
            continue

        if test_c.is_file() and not drop_c:
            backends.log(">> [Prune] leaving {}: no LLM_REPLACE marker".format(test_c))
        elif drop_c:
            test_c.unlink()
        if registered:
            buildinfo.unregister(name)
        shutil.rmtree(run_dir)

        backends.log(">> [Prune] deleted {}".format(", ".join(targets)))
        removed.append(name)

    if removed and not dry_run and not keep_index:
        _rewrite_index(out_root, removed)
    return removed


def _rewrite_index(out_root: Path, removed: List[str]) -> None:
    """Drop the pruned runs from runs.jsonl."""
    index = out_root / INDEX.name
    if not index.is_file():
        return

    gone = set(removed)
    kept = []
    for line in index.read_text().splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            kept.append(line)
            continue
        if record.get("name") not in gone:
            kept.append(line)
    index.write_text("".join(l + "\n" for l in kept))
