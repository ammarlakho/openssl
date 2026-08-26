"""Run a grid of generation parameters and save each result as its own test.

One sweep run = one (temperature, top_p, seed, penalty, ...) combination =
one self-contained directory under test/generated/:

    test/generated/<name>/
        <name>.c        the filled stub -- this is what the build compiles
        meta.json       model, endpoint, every sampling knob, timing, outcome
        prompt.txt      the exact prompt that was sent
        response.txt    the raw model reply, before splicing/sanitising

<name> encodes the model and the knobs that produced it, plus a timestamp, so
two runs never collide and a directory listing is already a readable result
table. Every successful run is registered in test/build.info (so `make
test/<name>` works) and appended to test/generated/runs.jsonl.

The grid comes from a JSON config so re-running with different parameters is a
config edit, not a code edit; --grid overrides individual axes from the command
line.
"""

import hashlib
import itertools
import json
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import backends, buildinfo, paths, stub
from .backends import BackendError, GenParams
from .context import ContextOptions, build_prompt

# Everything a sweep produces lives here, one directory per run.
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


class SweepError(Exception):
    """A sweep could not be planned or run."""


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
            raise SweepError("config not found: {}".format(path))
        try:
            loaded = json.loads(cfg_path.read_text())
        except json.JSONDecodeError as exc:
            raise SweepError("{}: {}".format(cfg_path, exc))
        unknown = set(loaded) - set(DEFAULT_CONFIG)
        if unknown:
            raise SweepError("unknown config keys: {}".format(", ".join(sorted(unknown))))
        config.update(loaded)
    return config


def parse_grid_override(entries: List[str]) -> Dict[str, List[Any]]:
    """--grid temperature=0.2,0.8 --grid seed=1,2,3 -> {"temperature": [...]}"""
    grid: Dict[str, List[Any]] = {}
    for entry in entries or []:
        axis, _, values = entry.partition("=")
        axis = axis.strip()
        if not values.strip():
            raise SweepError("--grid needs axis=v1,v2 (got {!r})".format(entry))
        grid[axis] = [v.strip() for v in values.split(",") if v.strip()]
    return grid


def normalise_grid(grid: Dict[str, Any]) -> Dict[str, List[Any]]:
    clean: Dict[str, List[Any]] = {}
    for axis, values in grid.items():
        if axis not in AXES:
            raise SweepError(
                "unknown grid axis {!r}; known axes: {}".format(
                    axis, ", ".join(sorted(AXES))))
        if not isinstance(values, (list, tuple)):
            values = [values]
        cast = AXIS_TYPES[axis]
        try:
            clean[axis] = [None if v is None else cast(v) for v in values]
        except (TypeError, ValueError) as exc:
            raise SweepError("bad value on axis {}: {}".format(axis, exc))
        if not clean[axis]:
            raise SweepError("axis {} has no values".format(axis))
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
        raise SweepError("unknown context keys: {}".format(", ".join(sorted(unknown))))
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


def _unique_dir(base: Path) -> Path:
    """Names carry a seconds-resolution stamp; make collisions impossible anyway."""
    if not base.exists():
        return base
    for n in itertools.count(2):
        candidate = base.with_name("{}_{}".format(base.name, n))
        if not candidate.exists():
            return candidate


def plan(config: Dict[str, Any], grid_override: Dict[str, List[Any]]) -> List[Dict[str, Any]]:
    """Every run this sweep will perform, before any of them happen."""
    grid = dict(config.get("grid") or {})
    grid.update(grid_override)
    points = expand_grid(normalise_grid(grid))

    repeats = int(config.get("repeats") or 1)
    if repeats < 1:
        raise SweepError("repeats must be >= 1")

    runs = []
    for point in points:
        for r in range(1, repeats + 1):
            runs.append({"point": point, "repeat": r if repeats > 1 else None})
    return runs


def run_sweep(
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

    out_root = Path(out_dir) if out_dir else OUT_DIR
    source = config["source"]
    test_fn = config.get("test_fn") or _default_test_fn(source)
    source_path = paths.resolve_under_repo(source)
    if not source_path.is_file():
        raise SweepError("source under test not found: {}".format(source_path))

    # Resolved once: every run in a sweep hits the same endpoint, and the model
    # name is part of every run's name.
    profile, api_url, model, _ = backends.resolve_profile(
        config.get("profile"), config.get("api_url"), config.get("model"))

    backends.log(">> [Sweep] {} run(s) | profile={} model={} | out={}".format(
        len(runs), profile, model, out_root))

    results = []
    for i, run in enumerate(runs, 1):
        point = run["point"]
        stamp = datetime.now().strftime("%y%m%d_%H%M%S")
        name = run_name(config.get("prefix") or "gen", model, point, stamp, run["repeat"])

        backends.log(">> [Sweep] ({}/{}) {} [{}]".format(
            i, len(runs), name,
            ", ".join("{}={}".format(k, v) for k, v in sorted(point.items())) or "server defaults"))

        record = {
            "name": name,
            "index": i,
            "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "profile": profile,
            "api_url": api_url,
            "model": model,
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
            record["dir"] = str((out_root / name).relative_to(paths.REPO_ROOT))
            results.append(record)
            continue

        run_dir = _unique_dir(out_root / name)
        name = run_dir.name
        record["name"] = name
        run_dir.mkdir(parents=True)

        test_c = run_dir / "{}.c".format(name)
        test_c.write_text(stub.generate_stub(name, test_fn, source_path))
        record["dir"] = str(run_dir.relative_to(paths.REPO_ROOT))
        record["source_file"] = str(test_c.relative_to(paths.REPO_ROOT))

        started = time.monotonic()
        try:
            prompt = build_prompt(source, _context_options(config, test_c))
            (run_dir / "prompt.txt").write_text(prompt)
            record["prompt_sha256"] = hashlib.sha256(prompt.encode()).hexdigest()[:16]

            params = GenParams(**point)
            reply = backends.run_remote(prompt, profile, api_url, model, params)
            (run_dir / "response.txt").write_text(reply)
            stub.fill_stub(test_c, reply)
            record["ok"] = True
        except Exception as exc:                       # noqa: BLE001 -- recorded, not swallowed
            record["error"] = "{}: {}".format(type(exc).__name__, exc)
            backends.log(">> [Sweep] FAILED {}: {}".format(name, record["error"]))
        record["duration_s"] = round(time.monotonic() - started, 1)

        if record["ok"] and register:
            rel_source = str(test_c.relative_to(paths.TEST_DIR))
            buildinfo.register(name, rel_source)
            record["registered"] = True
            backends.log(">> [Sweep] registered {} (SOURCE={})".format(name, rel_source))

        (run_dir / "meta.json").write_text(json.dumps(record, indent=2) + "\n")
        _append_index(out_root, record)
        results.append(record)

        delay = float(config.get("sleep") or 0)
        if delay and i < len(runs):
            time.sleep(delay)

    ok = sum(1 for r in results if r.get("ok"))
    if not dry_run:
        backends.log(">> [Sweep] done: {}/{} succeeded; index: {}".format(
            ok, len(results), (out_root / INDEX.name)))
        if ok:
            backends.log(">> [Sweep] next: ./thesis-work/mull-mutation/mull.sh compile-cov ./test/<name>")
    return results


def _append_index(out_root: Path, record: Dict[str, Any]) -> None:
    out_root.mkdir(parents=True, exist_ok=True)
    with (out_root / INDEX.name).open("a") as handle:
        handle.write(json.dumps(record) + "\n")
