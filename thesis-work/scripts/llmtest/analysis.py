"""Join generation records to mutation reports and produce the arm tables.

A run is recorded twice: once by the experiment (what was asked for -- the
arm, the task, the targets) and once by the mutation pass (what happened --
which mutants died). Neither half is meaningful alone, and the join is by run
name. Everything here is derived, so it can be re-run after any correction to
the triage or a re-mutation without regenerating a single test.

The measurement the experiment exists for is one boolean per Arm 2 run:

    compiled and passed, and killed zero of the mutants it was handed

That conjunction is hallucinated coverage. No judgement call is involved,
which is the point -- the rate across runs is the number to report.
"""

import json
from collections import Counter
from pathlib import Path
from statistics import median
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import experiment, mutants, mutation, paths

KILLED = mutants.KILLED_STATUSES

# Runs generated before the record carried an `arm` field are grouped by the
# prefix their config gave them. Deriving it beats rewriting the records: the
# mapping is visible here and the raw results stay exactly as they were
# written. Longest prefix wins.
PREFIX_ARMS = (
    ("ctxhead_", "0-head (pre-fix excerpts)"),
    ("ctxtest_", "0-test (fixed excerpts)"),
    ("a1b", "1b"),
    ("a1", 1),
    ("a2", 2),
)


def arm_of(record: Dict[str, Any]) -> Any:
    """The cell a run belongs to: what it recorded, or what its name says.

    An arm run more than once is more than one experiment, and the tables have
    to keep the cells apart or they average designs that differ. Runs now
    record the label themselves (`arm_cell`, set from `arm --cell`), which is
    the only reliable source: a re-run can differ in the excerpt length, the
    seed range or the target set, and none of that is visible in the arm
    number.

    The cells that predate the field are derived instead. Arm 1 was run twice
    before it existed: the five-per-call runs pinned temperature and used
    `context.lines` 50, the one-per-call runs left temperature unset and used
    250. The two markers agree exactly across all 100 runs, and the excerpt
    length is carried in the label because it is the variable a later cell
    varies. Arm 2 has exactly one such design -- ten seeds over the five
    clusters that survived the equivalence triage -- so it keeps the bare `2`.
    """
    cell = record.get("arm_cell")
    if cell:
        return cell
    arm = record.get("arm")
    if arm == 1:
        pinned = "temperature" in (record.get("params") or {})
        lines = (record.get("context") or {}).get("lines")
        return "1 ({}/call, L{})".format(5 if pinned else 1, lines)
    if arm is not None:
        return arm
    name = record.get("name") or ""
    for prefix, label in sorted(PREFIX_ARMS, key=lambda kv: -len(kv[0])):
        if name.startswith(prefix):
            return label
    return None


def generations(out_dir: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Every generation record, newest per name, keyed by name."""
    out: Dict[str, Dict[str, Any]] = {}
    for record in experiment.list_runs(out_dir):
        out[record["name"]] = record
    return out


def scored(names: Optional[Iterable[str]] = None) -> Dict[str, Dict[str, Any]]:
    """Every mutation record, newest per name, keyed by name."""
    wanted = set(names) if names is not None else None
    return {r["name"]: r for r in mutation.load_results(latest_only=True)
            if wanted is None or r["name"] in wanted}


def mutant_status(report: Path, focus: str) -> Dict[str, str]:
    """Mull id -> status, for one run's report.

    A record whose report is no longer on disk -- older runs point at a results
    directory that has since been renamed -- yields nothing rather than
    raising. Callers count those separately, because a missing report silently
    shrinks a union and would overstate what is still unkilled.
    """
    if not Path(report).is_file():
        return {}
    entry = mutants._entry(Path(report), focus)
    return {m.get("id"): m.get("status")
            for m in (entry.get("mutants") or []) if m.get("id")}


def join(out_dir: Optional[str] = None,
         focus: Optional[str] = None,
         only_source: bool = True) -> List[Dict[str, Any]]:
    """One run per row: what it was asked to do, and what it achieved.

    A generation with no mutation record is kept with `scored: False` rather
    than dropped -- a run that never compiled is a result, and silently
    excluding it would flatter every arm.

    Rows are restricted to `focus` by default. The arms are per source file,
    so pooling two files' Arm 2 runs into one table would be meaningless.
    """
    gens = generations(out_dir)
    if focus and only_source:
        gens = {k: v for k, v in gens.items()
                if (v.get("source") or focus) == focus}
    runs = scored(gens)
    rows = []
    for name, gen in sorted(gens.items()):
        source = gen.get("source") or focus
        row: Dict[str, Any] = {
            "name": name,
            "arm": arm_of(gen),
            "model": gen.get("model"),
            "params": gen.get("params") or {},
            "context": gen.get("context") or {},
            "source": source,
            "generated": bool(gen.get("ok")),
            "reached_model": reached_model(gen),
            "unwrapped_function": gen.get("unwrapped_function"),
            "cluster": gen.get("cluster"),
            "target_mutants": gen.get("target_mutants"),
            "scenario_text": gen.get("scenario_text"),
            "scenario_idx": gen.get("scenario_idx"),
            "scenario_seed": gen.get("scenario_seed"),
            "scored": False,
            "stage": None,
            "focus_killed": None,
            "focus_mutants": None,
            "targets": None,
            "targets_killed": None,
            "hallucinated": None,
        }
        run = runs.get(name)
        if run is not None:
            row["stage"] = run.get("stage")
            if run.get("ok"):
                stats = run.get("focus_stats") or {}
                status = stats.get("status") or {}
                row["scored"] = True
                row["focus_killed"] = (status.get("Killed", 0)
                                       + status.get("Timeout", 0))
                row["focus_mutants"] = stats.get("mutants")

                targets = row["target_mutants"]
                if targets and run.get("report"):
                    by_id = mutant_status(paths.REPO_ROOT / run["report"], source)
                    hit = sum(1 for t in targets if by_id.get(t) in KILLED)
                    row["targets"] = len(targets)
                    row["targets_killed"] = hit
                    # The test built and ran, so it "passed" in the only sense
                    # available: Mull requires a green baseline before it
                    # mutates anything.
                    row["hallucinated"] = (hit == 0)
        rows.append(row)
    return rows


# A generation that never got a response is not an observation of the model.
# The endpoint going away mid-cell is an outage, and counting those attempts in
# the denominator would report them as the model failing. They stay in the row
# file, flagged, so the outage is visible rather than deleted.
_NO_RESPONSE = ("could not reach", "timed out")


def reached_model(record: Dict[str, Any]) -> bool:
    """Whether this run got a response from the model at all."""
    if record.get("ok"):
        return True
    error = (record.get("error") or "").lower()
    return not any(marker in error for marker in _NO_RESPONSE)


def observed(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The rows that are observations of the model, outages excluded."""
    return [r for r in rows if r.get("reached_model", True)]


def in_arm(label: Any, arm: Any) -> bool:
    """Whether a cell label belongs to this arm.

    Labels are either the bare arm ("2", or the int 2 for the runs written
    before cells were recorded) or the arm followed by what makes the cell
    distinct ("1 (1/call, L50)"). Matching on the leading component is what
    lets a caller ask for an arm without enumerating its cells.
    """
    if label is None:
        return False
    return str(label) == str(arm) or str(label).startswith("{} ".format(arm))


def arm_cells(rows: Sequence[Dict[str, Any]], arm: Any) -> List[Any]:
    """Every cell label of one arm, in a stable order."""
    return sorted({r["arm"] for r in rows if in_arm(r["arm"], arm)}, key=str)


def corpus_mutants(focus: str) -> int:
    """Every mutant id Mull has ever reported for this file.

    Coverage-guided runs omit mutants they never reached, so the set a single
    arm sees depends on what its tests happened to execute. Using a per-arm
    denominator would therefore make the arms incomparable -- an arm that
    reached less of the file would appear to have covered more of it. The
    denominator is fixed here, over every report on disk.
    """
    reports, _missing = mutants.corpus_reports(mutation.load_results(latest_only=True))
    seen = set()
    for report in reports:
        seen.update(mutant_status(report, focus))
    return len(seen)


def union_killed(rows: Sequence[Dict[str, Any]], focus: str
                 ) -> Tuple[int, int, int]:
    """Mutants killed by at least one of these runs, the total, and how many
    runs could not be read."""
    runs = scored(r["name"] for r in rows)
    killed, seen = set(), set()
    unreadable = 0
    for row in rows:
        run = runs.get(row["name"])
        if not (run and run.get("ok") and run.get("report")):
            continue
        status_by_id = mutant_status(paths.REPO_ROOT / run["report"], focus)
        if not status_by_id:
            unreadable += 1
            continue
        for mid, status in status_by_id.items():
            seen.add(mid)
            if status in KILLED:
                killed.add(mid)
    return len(killed), len(seen), unreadable


def killed_sets(rows: Sequence[Dict[str, Any]], focus: str) -> List[frozenset]:
    """The set of mutants each scored run killed."""
    runs = scored(r["name"] for r in rows)
    out = []
    for row in rows:
        run = runs.get(row["name"])
        if not (run and run.get("ok") and run.get("report")):
            continue
        by_id = mutant_status(paths.REPO_ROOT / run["report"], focus)
        if by_id:
            out.append(frozenset(m for m, s in by_id.items() if s in KILLED))
    return out


def rarefied_union(sets: Sequence[frozenset], k: int, trials: int = 2000,
                   seed: int = 0) -> Optional[float]:
    """Mean union size over random subsets of `k` runs.

    A union grows with the number of runs, so comparing an arm of 10 against
    an arm of 50 on raw union measures the sample size, not the arm. Rarefying
    to a common k is what makes the comparison mean anything.
    """
    import random
    if len(sets) < k or k <= 0:
        return None
    rng = random.Random(seed)
    total = 0
    for _ in range(trials):
        total += len(frozenset().union(*rng.sample(list(sets), k)))
    return total / trials


# --------------------------------------------------------------------------
# Tables
# --------------------------------------------------------------------------

def _fmt(value, dash="-"):
    return dash if value is None else value


def table1(rows: Sequence[Dict[str, Any]], focus: str, groups=None,
           denominator: Optional[int] = None) -> str:
    """Arm comparison: usable rate, median kills, union.

    `denominator` is the file's whole mutant set, fixed across arms; see
    corpus_mutants.
    """
    groups = groups or sorted({r["arm"] for r in rows if r["arm"] is not None},
                              key=str)
    total_mutants = denominator if denominator is not None else corpus_mutants(focus)
    # k for the rarefied union: the smallest usable count across the arms
    # being compared, so every arm can actually be sampled at it.
    rows = observed(rows)
    usable_counts = [sum(1 for r in rows if r["arm"] == a and r["scored"])
                     for a in groups]
    k = min([c for c in usable_counts if c > 0], default=0)

    head = "{:<26} {:>8} {:>8} {:>9} {:>9} {:>9} {:>12}".format(
        "arm", "runs", "usable", "median", "best", "union",
        "union@n={}".format(k) if k else "union@n")
    out = [head, "-" * len(head)]
    for arm in groups:
        members = [r for r in rows if r["arm"] == arm]
        if not members:
            continue
        usable = [r for r in members if r["scored"]]
        kills = [r["focus_killed"] for r in usable if r["focus_killed"] is not None]
        u, total, unreadable = union_killed(members, focus)
        rare = rarefied_union(killed_sets(members, focus), k) if k else None
        out.append("{:<26} {:>8} {:>8} {:>9} {:>9} {:>9} {:>12}".format(
            str(arm), len(members),
            "{}/{}".format(len(usable), len(members)),
            "{:.0f}".format(median(kills)) if kills else "-",
            max(kills) if kills else "-",
            "{}/{}".format(u, total_mutants) if total_mutants else "-",
            "{:.1f}".format(rare) if rare is not None else "-"))
        if unreadable:
            out.append("{:<26} {}".format(
                "", "({} run(s) had no report on disk and are not in the "
                    "union above)".format(unreadable)))
    return "\n".join(out)


def table2(rows: Sequence[Dict[str, Any]]) -> str:
    """Arm 2 per-cluster: the hallucinated-coverage table, one block per cell.

    Cells are not pooled. A cluster's targets are whatever survived when the
    run was planned, so two Arm 2 runs against the same file can hand the same
    cluster different mutants; a pooled rate would have two denominators.
    """
    cells = arm_cells(observed(rows), 2)
    if len(cells) <= 1:
        return _table2_cell(rows)
    blocks = []
    for cell in cells:
        members = [r for r in rows if r["arm"] == cell]
        blocks.append("{}\n{}".format(cell, _table2_cell(members)))
    return "\n\n".join(blocks)


def _table2_cell(rows: Sequence[Dict[str, Any]]) -> str:
    """One Arm 2 cell's per-cluster table."""
    arm2 = [r for r in observed(rows) if in_arm(r["arm"], 2)]
    head = "{:<18} {:>8} {:>6} {:>10} {:>12} {:>12} {:>10}".format(
        "cluster", "targets", "runs", "usable", "killed>=1", "killed 0", "halluc.")
    out = [head, "-" * len(head)]
    for cluster in sorted({r["cluster"] for r in arm2 if r["cluster"]}):
        members = [r for r in arm2 if r["cluster"] == cluster]
        usable = [r for r in members if r["scored"] and r["targets"] is not None]
        some = [r for r in usable if r["targets_killed"]]
        none = [r for r in usable if r["targets_killed"] == 0]
        targets = members[0]["targets"] or len(members[0]["target_mutants"] or [])
        out.append("{:<18} {:>8} {:>6} {:>10} {:>12} {:>12} {:>10}".format(
            cluster, targets, len(members),
            "{}/{}".format(len(usable), len(members)),
            len(some), len(none),
            "{:.0%}".format(len(none) / len(usable)) if usable else "-"))
    usable = [r for r in arm2 if r["scored"] and r["targets"] is not None]
    none = [r for r in usable if r["targets_killed"] == 0]
    out.append("-" * len(head))
    out.append("{:<18} {:>8} {:>6} {:>10} {:>12} {:>12} {:>10}".format(
        "ALL", "", len(arm2), "{}/{}".format(len(usable), len(arm2)),
        len(usable) - len(none), len(none),
        "{:.0%}".format(len(none) / len(usable)) if usable else "-"))
    return "\n".join(out)


def defect_mix(rows: Sequence[Dict[str, Any]]) -> str:
    """Why runs failed, per arm -- the defect comparison across arms.

    The "mutate" stage is not an infrastructure failure: Mull runs the test
    unmodified before it mutates anything and refuses to continue if that
    warm-up fails. Every mutate-stage failure in this corpus is that case, so
    the column means "compiled, but the assertions do not hold on the correct
    implementation" -- and a run that reaches `scored` has provably compiled
    and passed, which is what makes the Arm 2 boolean sound.
    """
    head = "{:<26} {:>10} {:>10} {:>14} {:>12}".format(
        "arm", "generated", "build-fail", "fails-on-good", "unwrapped")
    out = [head, "-" * len(head)]
    # Arm labels are a mix of ints (1, 2) and the derived strings for the
    # ablation cells, so they can only be ordered as text.
    for arm in sorted({r["arm"] for r in rows if r["arm"] is not None}, key=str):
        members = [r for r in observed(rows) if r["arm"] == arm]
        stages = Counter(r["stage"] for r in members if not r["scored"])
        out.append("{:<26} {:>10} {:>10} {:>14} {:>12}".format(
            str(arm),
            sum(1 for r in members if r["generated"]),
            stages.get("build", 0), stages.get("mutate", 0),
            sum(1 for r in members if r["unwrapped_function"])))
    return "\n".join(out)


def write_rows(rows: Sequence[Dict[str, Any]], path: Path) -> Path:
    """Persist the joined table so every number above can be re-derived."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    return path


# --------------------------------------------------------------------------
# Table 3: what the model proposed, against what the triage says is untested
# --------------------------------------------------------------------------

# One row per behaviour the surviving mutants actually require, derived from
# the triage rather than invented: each is the stimulus or oracle that some
# never-killed mutant needs. The patterns are a first pass over the model's
# own sentences -- deliberately generous, since the interesting number is how
# often a behaviour is proposed *at all*, and a false positive is the
# conservative error when the claim is "the model never mentions this".
SCENARIO_CLASSES = (
    ("round-trip / happy path", ("round.?trip", "encrypt.*then.*decrypt",
                                 "decrypt.*matches", "recover.*plaintext",
                                 "known.answer", "test vector")),
    ("free / reuse / duplicate a chain", ("bio_free", "free the", "freeing",
                                          "reuse", "re-use", "bio_dup",
                                          "bio_pop", "bio_push", "lifecycle",
                                          "leak")),
    ("partial / short reads", ("partial read", "short read", "small buffer",
                              "chunk", "byte at a time", "incremental read",
                              "read.{0,12}in pieces", "smaller than")),
    ("retry / non-blocking", ("retry", "should_retry", "non.?blocking",
                              "would block", "bio pair", "eof_return")),
    ("payload larger than ENC_MIN_CHUNK", ("enc_min_chunk", "large (payload|input|buffer|data)",
                                           "more than 256", "[0-9]{3,} bytes",
                                           "4096", "8192", "1024")),
    ("stream cipher / block size 1", ("stream cipher", "rc4", "chacha",
                                      "block size (of )?1", "blocksize.{0,4}1")),
    ("zero-length or NULL write/read", ("zero.length", "zero.byte", "empty (input|buffer|write|read)",
                                        "null (buffer|input|pointer)", "0 bytes",
                                        "length of 0")),
    ("cipher status / error path", ("cipher_status", "get_cipher_status",
                                    "bad decrypt", "corrupt", "tamper",
                                    "wrong key", "invalid padding", "error path")),
    ("ctrl / flush / pending", ("bio_ctrl", "wpending", "pending", "flush",
                                "bio_reset", "ctrl_reset", "eof")),
)


def classify_scenario(text: str) -> List[str]:
    """Every class a scenario sentence matches; [] means none of them."""
    import re as _re
    low = text.lower()
    return [name for name, patterns in SCENARIO_CLASSES
            if any(_re.search(p, low) for p in patterns)]


def table3(scenarios: Dict[str, Any]) -> str:
    """How often each untested behaviour is proposed, out of all scenarios."""
    sentences = [s for sample in scenarios.get("samples", [])
                 for s in (sample.get("scenarios") or [])]
    total = len(sentences)
    tagged = [(s, classify_scenario(s)) for s in sentences]

    head = "{:<38} {:>10} {:>8}".format("behaviour", "scenarios", "share")
    out = [head, "-" * len(head)]
    for name, _ in SCENARIO_CLASSES:
        n = sum(1 for _, classes in tagged if name in classes)
        out.append("{:<38} {:>10} {:>8}".format(
            name, "{}/{}".format(n, total),
            "{:.0%}".format(n / total) if total else "-"))
    unmatched = sum(1 for _, classes in tagged if not classes)
    out.append("-" * len(head))
    out.append("{:<38} {:>10} {:>8}".format(
        "(matched no class)", "{}/{}".format(unmatched, total),
        "{:.0%}".format(unmatched / total) if total else "-"))
    distinct = len({s.lower().rstrip(".") for s in sentences})
    out.append("")
    out.append("{} scenario sentences, {} distinct".format(total, distinct))
    return "\n".join(out)


def table3_hand(classification: Dict[str, Any], scenarios: Dict[str, Any]) -> str:
    """Table 3 from the hand classification, which is the reportable version.

    The regex pass above is a triage aid, not a result: it keys on wording,
    and the model describes behaviour in terms of the file's own functions
    rather than the vocabulary the classes are written in. Fifty sentences is
    small enough to read, so the reported table is the read one -- and the
    file it comes from lists every scenario id under every behaviour, so the
    classification can be checked rather than trusted.
    """
    total = sum(len(s.get("scenarios") or [])
                for s in scenarios.get("samples", []))
    head = "{:<48} {:>10} {:>8}".format("behaviour a surviving mutant needs",
                                        "proposed", "share")
    out = [head, "-" * len(head)]
    for name, entry in classification.get("behaviours", {}).items():
        n = len(entry.get("scenarios") or [])
        out.append("{:<48} {:>10} {:>8}".format(
            name, "{}/{}".format(n, total),
            "{:.0%}".format(n / total) if total else "-"))

    other = classification.get("what_was_proposed_instead") or {}
    if other:
        out.append("")
        out.append("{:<48} {:>10} {:>8}".format(
            "what was proposed instead", "count", "share"))
        out.append("-" * len(head))
        for name, ids in sorted(other.items(), key=lambda kv: -len(kv[1])):
            out.append("{:<48} {:>10} {:>8}".format(
                name, "{}/{}".format(len(ids), total),
                "{:.0%}".format(len(ids) / total) if total else "-"))
    return "\n".join(out)


def suspect_kills(rows: Sequence[Dict[str, Any]], focus: str,
                  triage: Dict[str, Dict]) -> List[Dict[str, Any]]:
    """Kills of mutants the triage proved equivalent -- i.e. false kills.

    Mull counts a timeout as a kill, which is the right default: a mutant that
    hangs the suite has been detected. It is not right for an *equivalent*
    mutant, which by construction cannot change behaviour, so a timeout there
    can only be flakiness or a loaded machine. Because the triage says which
    mutants those are, it can be used to audit the measurement rather than
    only to fix the denominator -- and a genuine "Killed" against an
    equivalent mutant would mean the equivalence argument is wrong and needs
    revisiting.
    """
    equivalent = {mid for mid, e in triage.items()
                  if e.get("bucket") == "equivalent"}
    out = []
    runs = scored(r["name"] for r in rows)
    for row in rows:
        run = runs.get(row["name"])
        if not (run and run.get("ok") and run.get("report")):
            continue
        for mid, status in mutant_status(paths.REPO_ROOT / run["report"], focus).items():
            if mid in equivalent and status in KILLED:
                out.append({"run": row["name"], "arm": row["arm"],
                            "mutant": mid, "status": status})
    return out
