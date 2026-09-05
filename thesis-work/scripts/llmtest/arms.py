"""The three arms of the scoping-vs-implementation experiment.

The question is whether the model fails to test the untested parts of a source
file because it *cannot*, or because it never *thinks to*. Answering it needs
two prompts that differ in one respect only:

  Arm 0  the fixed task string, as the historical corpus used
  Arm 1  a task string the model wrote for itself, having seen only the source
  Arm 2  the surviving mutants, handed over verbatim

Arm 1 runs in two stages because the splicer expects one test body per run:
stage 1 asks for scenarios and nothing else, stage 2 feeds each scenario
through the ordinary experiment path as its task. Stage 1 is a result on its
own -- what the model proposes, before any test exists, is the direct
measurement of what it does not think to test.

No task string anywhere here is hand-written. Arm 1's come from the model,
Arm 2's from Mull. That is what makes the design transfer to another file.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import backends, experiment, mutants, mutation, paths
from .backends import GenParams

ARMS_DIR = paths.EXPERIMENTS / "arms"

# Stage 1 of Arm 1. Deliberately free of hints: naming retry, EOF, padding,
# block size or lifecycle would reintroduce the hand-written arm through the
# back door and void the result. No reference tests, no stub, no contract --
# the model sees the source and nothing else.
SCENARIO_PROMPT = """Below is the complete source of {source} from OpenSSL.

{code}

Name one test for this file.

Output a single sentence saying what the test does. No code, no explanation,
no preamble, no numbering.
"""

# Asking for one sentence per call, rather than N per call, is deliberate.
# Sample size is set by the number of seeds, not by N, so the two were never
# coupled; and measured against the five-scenario version, the model's first
# proposal was also its best -- median mutants killed fell 30, 32, 28, 18, 14
# across positions one to five. Asking for five spent 40% of the budget on the
# model's fourth and fifth ideas. Bundling all five into one test body was
# worse still: 0 of 9 runs produced a test that compiled and passed, against
# 44% when each scenario got its own run.

# "1. Round-trips a payload." / "1) ..." / "- ..." -- models number in all of
# these ways and the numbering is not the data, so it is stripped.
_NUMBERED_RE = re.compile(r"^\s*(?:[-*]\s*)?(?:\(?(\d{1,2})[.)\]]|\#(\d{1,2}))\s+(.*\S)\s*$")
_BARE_BULLET_RE = re.compile(r"^\s*[-*]\s+(.*\S)\s*$")


class ArmError(Exception):
    """An arm could not be planned or run."""


def _grid(temperature: Optional[float], seed: int) -> Dict[str, List[Any]]:
    """The one-point grid a single arm run uses.

    Only the seed is always pinned -- it is what gives runs distinct names.
    Temperature is sent only if the caller asked for one, so the default is
    whatever the endpoint does on its own.
    """
    grid: Dict[str, List[Any]] = {"seed": [seed]}
    if temperature is not None:
        grid["temperature"] = [temperature]
    return grid


# --------------------------------------------------------------------------
# Arm 1, stage 1: scenario generation
# --------------------------------------------------------------------------

def parse_scenario(reply: str) -> str:
    """The one sentence a scenario call returns.

    Models still occasionally number a single answer or wrap it in a fence, so
    both are tolerated; anything after the first substantive line is dropped
    rather than concatenated, because a second sentence would silently
    reintroduce the multi-scenario prompt this replaced.
    """
    for line in reply.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("```") or stripped.startswith("#"):
            continue
        match = _NUMBERED_RE.match(stripped)
        if match:
            return match.group(3).strip()
        bullet = _BARE_BULLET_RE.match(stripped)
        if bullet:
            return bullet.group(1).strip()
        return stripped
    return ""


def parse_scenarios(reply: str, expected: Optional[int] = None) -> List[str]:
    """The numbered lines of a scenario response, in order.

    Kept lenient about how the model numbers and strict about what counts as a
    scenario: a line has to be prose, not a fence, a heading or a stray blank.
    Nothing is invented to reach `expected` -- a short answer is a finding.
    """
    out: List[str] = []
    for line in reply.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("```") or stripped.startswith("#"):
            continue
        match = _NUMBERED_RE.match(stripped)
        if match:
            out.append(match.group(3).strip())
            continue
        if out:
            # Only accept bare bullets once numbering has already appeared, so
            # a preamble sentence cannot be mistaken for scenario one.
            bullet = _BARE_BULLET_RE.match(stripped)
            if bullet:
                out.append(bullet.group(1).strip())
    if expected is not None:
        out = out[:expected]
    return out


def generate_scenarios(source: str, seeds: Sequence[int],
                       profile: Optional[str] = None,
                       model: Optional[str] = None,
                       api_url: Optional[str] = None,
                       temperature: Optional[float] = None,
                       top_p: Optional[float] = None,
                       out_path: Optional[Path] = None) -> Dict[str, Any]:
    """One scenario call per seed, one sentence each.

    Sampling knobs default to None, meaning the endpoint's own defaults are
    used and nothing is sent. That is the condition a user of the tool would
    actually be in, and it removes a parameter that has to be justified;
    temperature in particular was measured to have no effect on mutation
    score in this pipeline (r = +0.03, p = 0.84).

    Each sample keeps a one-element `scenarios` list as well as `scenario`, so
    records written before and after this change read the same way.
    """
    src = paths.resolve_under_repo(source)
    if not src.is_file():
        raise ArmError("source under test not found: {}".format(src))
    endpoint = backends.resolve_profile(profile, api_url, model)

    prompt = SCENARIO_PROMPT.format(
        source=source, code=src.read_text(errors="replace"))

    record: Dict[str, Any] = {
        "source": source,
        "scenarios_per_call": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "profile": endpoint.profile,
        "model": endpoint.model,
        "temperature": temperature,
        "top_p": top_p,
        "prompt": prompt,
        "samples": [],
    }

    for seed in seeds:
        sample: Dict[str, Any] = {"seed": seed, "ok": False, "error": None}
        try:
            reply = backends.run_prompt(prompt, endpoint, GenParams(
                temperature=temperature, top_p=top_p, seed=seed))
            sample["response"] = reply
            text = parse_scenario(reply)
            sample["scenario"] = text
            sample["scenarios"] = [text] if text else []
            sample["ok"] = bool(text)
            if not text:
                sample["error"] = "no sentence found in the response"
            backends.log(">> [Arm1/scenarios] seed {}: {}".format(
                seed, text[:100] if text else "EMPTY"))
        except Exception as exc:                       # noqa: BLE001
            sample["error"] = "{}: {}".format(type(exc).__name__, exc)
            sample["scenarios"] = []
            backends.log(">> [Arm1/scenarios] seed {} FAILED: {}".format(
                seed, sample["error"]))
        record["samples"].append(sample)

    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(record, indent=2) + "\n")
    return record


def load_scenarios(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ArmError("unreadable scenarios {}: {}".format(path, exc))


# --------------------------------------------------------------------------
# Arm 1, stage 2: one generation per scenario
# --------------------------------------------------------------------------

# Arm 1b's task: the same scenarios, handed over together instead of one at a
# time. The only added words are the instruction to cover them all, because
# multiplicity is exactly the variable under test -- anything else would make
# 1b differ from 1 in more than one respect.
BUNDLE_HEADER = ("Cover all {n} of the following scenarios in the single test "
                 "body:\n\n")


def bundle_task(texts: Sequence[str]) -> str:
    numbered = "\n".join("{}. {}".format(i, s) for i, s in enumerate(texts, 1))
    return BUNDLE_HEADER.format(n=len(texts)) + numbered


def run_arm1(config: Dict[str, Any], scenarios: Dict[str, Any],
             temperature: Optional[float] = None,
             limit: Optional[int] = None,
             register: bool = True,
             bundle: bool = False,
             prefix: Optional[str] = None,
             cell: Optional[str] = None) -> List[Dict[str, Any]]:
    """Feed the proposed scenarios through the ordinary experiment path.

    The scenario becomes the task and nothing else changes -- that is the
    whole point, so that Arm 1 and Arm 0 differ in the task string alone.

    `bundle` switches from one generation per scenario (Arm 1) to one
    generation per scenario *call* (Arm 1b), so a seed's five scenarios are
    asked for in a single test body. It trades per-scenario attribution --
    which is what tells you which proposal earned a kill -- for more
    assertions per run, and which of those wins is an empirical question.

    `prefix` renames the runs and `cell` labels them for the analysis. Arm 1
    has now been run under three designs against the same file, and neither a
    shared run-name prefix nor an inferred label keeps them apart reliably:
    the name is what a person reads in `test/`, the recorded `arm_cell` is
    what `analysis.arm_of` groups on. Give both whenever a new cell is added,
    or its runs pool with an existing one.
    """
    label = "1b" if bundle else 1
    tag = "Arm1b" if bundle else "Arm1"
    results: List[Dict[str, Any]] = []

    if bundle:
        jobs = [(s["seed"], None, s.get("scenarios") or [])
                for s in scenarios.get("samples", [])
                if s.get("scenarios")]
    else:
        jobs = [(s["seed"], i, [text])
                for s in scenarios.get("samples", [])
                for i, text in enumerate(s.get("scenarios") or [], 1)]
    if limit is not None:
        jobs = jobs[:limit]

    backends.log(">> [{}] {} generation(s) to run".format(tag, len(jobs)))
    for n, (seed, idx, texts) in enumerate(jobs, 1):
        task = bundle_task(texts) if bundle else texts[0]
        backends.log(">> [{}] ({}/{}) seed {}{}: {}".format(
            tag, n, len(jobs), seed,
            "" if idx is None else " scenario {}".format(idx),
            ("{} scenarios".format(len(texts)) if bundle else texts[0][:80])))
        base = prefix or ("a1b" if bundle else "a1")
        cfg = dict(config)
        cfg["task"] = task
        cfg["prefix"] = base if bundle else "{}n{}".format(base, idx)
        extra = {"arm": label, "scenario_text": task, "scenario_idx": idx,
                 "scenario_seed": seed, "scenario_count": len(texts)}
        if cell:
            extra["arm_cell"] = cell
        results.extend(experiment.run_experiment(
            cfg,
            grid_override=_grid(temperature, seed),
            register=register,
            quiet=True,
            extra=extra,
        ))
    return results


# --------------------------------------------------------------------------
# Arm 2: one generation per surviving-mutant cluster
# --------------------------------------------------------------------------

def arm2_clusters(source: str, triage_path: Optional[Path] = None,
                  drop: Sequence[str] = ("equivalent",)
                  ) -> Tuple[List[mutants.Cluster], str]:
    """The surviving-mutant clusters this run will be scored against."""
    reports, missing = mutants.corpus_reports(mutation.load_results(latest_only=True))
    if not reports:
        raise ArmError("no recorded mutation reports; run `mutate` first")
    if missing:
        backends.log(">> [Arm2] {} recorded run(s) have no report on disk and "
                     "are not in this denominator".format(len(missing)))
    alive, _covered = mutants.never_killed(reports, source)
    if triage_path is not None:
        triage = mutants.load_triage(triage_path)
        alive, unknown = mutants.apply_triage(alive, triage, drop)
        if unknown:
            backends.log(">> [Arm2] {} mutant(s) not in the triage were kept: "
                         "{}".format(len(unknown), ", ".join(unknown)))
    text = mutants.report_source(reports[0], source) or \
        paths.resolve_under_repo(source).read_text()
    return mutants.cluster(alive, mutants.find_functions(text)), text


# A cluster's targets are whatever had survived when the run was planned, and
# that set moves: every mutation pass can kill one, and a pass can also expose
# a mutant no test had reached. A cell interrupted halfway therefore cannot be
# finished by re-planning it -- the second half would be scored against a
# different set. Snapshotting the plan is what makes the completion runs part
# of the same cell.

def save_target_snapshot(clusters: Sequence[mutants.Cluster], path: Path,
                         source: str, drop: Sequence[str],
                         note: Optional[str] = None) -> Path:
    """Write the planned clusters and their targets, verbatim."""
    import dataclasses
    snapshot = {
        "source": source,
        "drop": list(drop),
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": note or "",
        "clusters": [{"function": c.function, "start": c.start, "end": c.end,
                      "mutants": [dataclasses.asdict(m) for m in c.mutants]}
                     for c in clusters],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot, indent=1) + "\n")
    return path


def load_target_snapshot(path: Path) -> List[mutants.Cluster]:
    """The clusters a previous plan recorded, rebuilt as they were."""
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ArmError("unreadable target snapshot {}: {}".format(path, exc))
    return [mutants.Cluster(function=c["function"], start=c["start"],
                            end=c["end"],
                            mutants=[mutants.Mutant(**m) for m in c["mutants"]])
            for c in data.get("clusters") or []]


def arm2_source_text(source: str) -> str:
    """The source the mutant line numbers refer to.

    Taken from a recorded report where there is one, so a snapshot planned
    against an older report still renders the lines the mutants were found on.
    """
    reports, _missing = mutants.corpus_reports(
        mutation.load_results(latest_only=True))
    text = mutants.report_source(reports[0], source) if reports else None
    return text or paths.resolve_under_repo(source).read_text()


def run_arm2(config: Dict[str, Any], clusters: Sequence[mutants.Cluster],
             source_text: str, seeds: Sequence[int],
             temperature: Optional[float] = None,
             register: bool = True,
             limit: Optional[int] = None,
             prefix: Optional[str] = None,
             cell: Optional[str] = None) -> List[Dict[str, Any]]:
    """One run per (cluster, seed), the cluster's mutants handed over verbatim.

    `prefix` and `cell` mean what they do in `run_arm1`. A second Arm 2 run
    against the same file is not the same cell as the first unless it was
    handed the same targets under the same settings, and a cluster's target
    set changes as the corpus kills mutants and the triage drops them -- so a
    re-run needs its own `cell` or its per-cluster rates pool two different
    denominators.
    """
    results: List[Dict[str, Any]] = []
    jobs = [(c, s) for c in clusters for s in seeds]
    if limit is not None:
        jobs = jobs[:limit]

    backends.log(">> [Arm2] {} run(s) over {} cluster(s)".format(
        len(jobs), len(clusters)))
    for n, (group, seed) in enumerate(jobs, 1):
        block = mutants.format_block(group.mutants, source_text, config["source"])
        backends.log(">> [Arm2] ({}/{}) {} seed {} ({} target(s))".format(
            n, len(jobs), group.function, seed, len(group.mutants)))
        cfg = dict(config)
        cfg["task"] = block
        cfg["prefix"] = "{}_{}".format(prefix or "a2", group.function)
        extra = {"arm": 2, "cluster": group.function,
                 "target_mutants": [m.id for m in group.mutants]}
        if cell:
            extra["arm_cell"] = cell
        results.extend(experiment.run_experiment(
            cfg,
            grid_override=_grid(temperature, seed),
            register=register,
            quiet=True,
            extra=extra,
        ))
    return results
