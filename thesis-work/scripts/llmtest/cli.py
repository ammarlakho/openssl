"""Command line entry point. See ../llm_test.py.

Subcommands:
  generate  assemble a prompt, run a model, print or splice the result
  context   print the assembled prompt without calling a model
  stub      print a fresh test .c skeleton
  fill      splice a generated body into an existing stub
  experiment  run a grid of sampling parameters, one saved test per point
  mutate    run Mull over generated tests and record the scores
  mutants   cluster surviving mutants into a mutant-directed task block
  mutation-report  print the recorded scores as a table or CSV
"""

import argparse
import sys
import time
from pathlib import Path

from . import (analysis, arms, backends, buildinfo, experiment, mutants,
               mutation, paths, stub)
from . import context as context_mod
from .context import (DEFAULT_REF_SLICE, ContextError, ContextOptions,
                      build_contract_only, build_prompt)
from .backends import BackendError, GenParams
from .stub import StubError

# Applied by `generate` when the caller passes no context arguments at all.
DEFAULT_TASK = "AES-256 CBC BIO round-trip vs fixed vectors"
DEFAULT_SOURCE = "crypto/evp/bio_enc.c"
DEFAULT_INTO = "test/generated_test.c"


def _context_parser() -> argparse.ArgumentParser:
    """Flags shared by `generate` and `context`."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--snippet",
        action="store_true",
        help="generate only the test body, for splicing into a stub",
    )
    parser.add_argument(
        "--full-source",
        action="store_true",
        help="no-op, kept for compatibility: the whole source is the default",
    )
    parser.add_argument("--notes", action="store_true", help="list NOTES*.md at the repo root")
    parser.add_argument("--task", default="", help="free-form scenario description")
    parser.add_argument(
        "--keywords",
        default="",
        help="comma-separated extra search terms for picking reference tests",
    )
    parser.add_argument(
        "--impl-lines",
        type=int,
        default=None,
        help="truncate the source under test to its first N lines "
             "(default: no truncation)",
    )
    parser.add_argument("--refs", type=int, default=None, help="number of reference tests")
    parser.add_argument("--lines", type=int, default=None, help="lines per reference test")
    parser.add_argument(
        "--ref-slice",
        choices=context_mod.REF_SLICES,
        default=None,
        help="where each reference excerpt starts: 'test' (default) counts "
             "--lines from the first test function, 'head' from line 1 -- the "
             "pre-fix behaviour, kept so the context ablation has both cells",
    )
    parser.add_argument(
        "--stub",
        default=None,
        help="stub .c to show the model in snippet mode (generate: defaults to --into)",
    )
    return parser


def _params_parser() -> argparse.ArgumentParser:
    """Sampling knobs."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--temperature", type=float, default=None)
    parser.add_argument("--top-p", type=float, default=None)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=None,
        help="cap on generated tokens; raise this if output comes back truncated",
    )
    parser.add_argument(
        "--reasoning-effort",
        choices=backends.CLI_EFFORTS,
        default=None,
        help="reasoning models (gpt-oss: low|medium|high; the claude profile "
             "also takes xhigh|max); ignored by servers that do not support it",
    )
    parser.add_argument(
        "--frequency-penalty",
        type=float,
        default=None,
        help="OpenAI repetition knob (~-2..2, 0=off). Ollama maps it onto "
             "llama.cpp's repeat_penalty; vLLM implements it natively",
    )
    parser.add_argument("--presence-penalty", type=float, default=None)
    parser.add_argument(
        "--repetition-penalty",
        type=float,
        default=None,
        help="vLLM-only multiplicative repetition penalty (~1.0..2.0, 1.0=off); "
             "ignored by servers that do not know the field",
    )
    return parser


def _params_from(args: argparse.Namespace) -> GenParams:
    return GenParams(
        temperature=args.temperature,
        top_p=args.top_p,
        seed=args.seed,
        max_tokens=args.max_tokens,
        reasoning_effort=args.reasoning_effort,
        frequency_penalty=args.frequency_penalty,
        presence_penalty=args.presence_penalty,
        repetition_penalty=args.repetition_penalty,
    )


def _options_from(args: argparse.Namespace) -> ContextOptions:
    # --full-source is now the behaviour, so it only survives as a no-op flag.
    return ContextOptions(
        snippet=args.snippet,
        notes=args.notes,
        task=args.task,
        keywords=[k for k in args.keywords.split(",") if k.strip()],
        refs=args.refs,
        lines=args.lines,
        stub_path=args.stub,
        impl_lines=None if args.full_source else args.impl_lines,
        ref_slice=args.ref_slice or DEFAULT_REF_SLICE,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm_test.py",
        description="Generate OpenSSL unit tests with an LLM.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    shared = _context_parser()
    sampling = _params_parser()

    gen = sub.add_parser(
        "generate",
        parents=[shared, sampling],
        help="run a model and print or splice the generated test",
    )
    gen.add_argument("source", nargs="?", help="path to the source file under test")
    gen.add_argument("--into", help="stub .c file to splice the result into")
    gen.add_argument("--model", help="override the model name")
    gen.add_argument("--profile", help="endpoint profile name (default: gptoss)")
    gen.add_argument("--api-url", help="endpoint URL, overriding the profile")

    ctx = sub.add_parser("context", parents=[shared], help="print the assembled prompt")
    ctx.add_argument("source", nargs="?", help="path to the source file under test")
    ctx.add_argument(
        "--contract-only",
        action="store_true",
        help="print just the rules document",
    )

    st = sub.add_parser("stub", help="print a test .c skeleton")
    st.add_argument("program", help="program basename, e.g. generated_test")
    st.add_argument("function", help="test function name, e.g. test_bio_enc_roundtrip")
    st.add_argument(
        "--source",
        default=None,
        help="source under test; its API symbols decide the stub's includes",
    )

    ex = sub.add_parser(
        "experiment",
        help="run a grid of sampling parameters, saving one test per point",
    )
    ex.add_argument("config", nargs="?", help="experiment config JSON (see thesis-work/experiments/configs/)")
    ex.add_argument(
        "--grid",
        action="append",
        default=[],
        metavar="AXIS=V1,V2",
        help="override one grid axis, repeatable "
             "(e.g. --grid temperature=0.2,0.8 --grid seed=1,2,3)",
    )
    ex.add_argument("--source", help="override the source under test")
    ex.add_argument("--task", help="override the scenario description")
    ex.add_argument("--test-fn", help="override the test function name")
    ex.add_argument("--prefix", help="override the leading name component")
    ex.add_argument("--model", help="override the model name")
    ex.add_argument("--profile", help="endpoint profile name")
    ex.add_argument("--api-url", help="endpoint URL, overriding the profile")
    ex.add_argument("--repeats", type=int, default=None, help="runs per grid point")
    ex.add_argument("--sleep", type=float, default=None, help="seconds between calls")
    ex.add_argument("--limit", type=int, default=None, help="stop after N runs")
    ex.add_argument("--out-dir", default=None, help="override test/generated")
    ex.add_argument(
        "--no-register",
        action="store_true",
        help="skip the test/build.info entry for each generated test",
    )
    ex.add_argument(
        "--dry-run",
        action="store_true",
        help="print the planned runs and their names; call no model, write nothing",
    )

    runs = sub.add_parser("runs", help="list the runs saved under test/generated")
    runs.add_argument("--out-dir", default=None, help="override test/generated")

    pr = sub.add_parser(
        "prune",
        help="delete runs: their directory and their build.info entries",
    )
    pr.add_argument("names", nargs="*", help="run names to delete")
    pr.add_argument("--all", action="store_true", help="delete every run")
    pr.add_argument("--failed", action="store_true", help="delete runs whose generation failed")
    pr.add_argument("--out-dir", default=None, help="override test/generated")
    pr.add_argument(
        "--keep-index",
        action="store_true",
        help="leave runs.jsonl alone instead of dropping the pruned runs from it",
    )
    pr.add_argument(
        "--dry-run",
        action="store_true",
        help="print what would be deleted; delete nothing",
    )

    mut = sub.add_parser(
        "mutate",
        help="build and mutation-test generated tests, recording each score",
    )
    mut.add_argument("names", nargs="*", help="run names (default: --all)")
    mut.add_argument("--all", action="store_true", help="every successful run")
    mut.add_argument("--out-dir", default=None, help="override test/generated")
    mut.add_argument(
        "--no-configure",
        action="store_true",
        help="skip the coverage reconfigure; the tree is already built for it",
    )
    mut.add_argument(
        "--no-build",
        action="store_true",
        help="skip make; the test binaries already exist",
    )
    mut.add_argument(
        "--source",
        help="source under test for the focus score, used for tests that have "
             "no generated run to read it from (default: {})".format(DEFAULT_SOURCE),
    )
    mut.add_argument(
        "--rerun",
        choices=sorted(mutation.RERUN_MODES),
        default="none",
        help="which already-recorded tests to run again: none (default, skip "
             "anything with a record), failed, scored, or all",
    )

    rep = sub.add_parser(
        "mutation-report",
        help="print the scores recorded under thesis-work/experiments/results",
    )
    rep.add_argument(
        "--csv",
        action="store_true",
        help="print the running CSV record (thesis-work/experiments/results/results.csv)",
    )
    rep.add_argument(
        "--rebuild-csv",
        action="store_true",
        help="regenerate that CSV from results.jsonl (source of truth), "
             "one row per test name -- the newest run of each",
    )
    rep.add_argument(
        "--history",
        action="store_true",
        help="every recorded run, not just the newest per test",
    )
    rep.add_argument(
        "--survivors",
        metavar="NAME",
        help="list the surviving mutants of one recorded run",
    )

    mt = sub.add_parser(
        "mutants",
        help="cluster surviving mutants and emit the mutant-directed task block",
    )
    mt.add_argument(
        "--source",
        default=DEFAULT_SOURCE,
        help="source under test (default: {})".format(DEFAULT_SOURCE),
    )
    mt.add_argument(
        "--report",
        default=None,
        help="one Elements report: what that run left alive. Default is the "
             "whole recorded corpus: what no run has ever killed",
    )
    mt.add_argument(
        "--triage",
        default=None,
        help="triage JSON (thesis-work/experiments/triage/<file>.json): drops "
             "the mutants classed equivalent, which is the corrected "
             "denominator every Arm 2 number is against",
    )
    mt.add_argument(
        "--drop",
        default="equivalent",
        help="with --triage, which classes to exclude, comma-separated from "
             "{}; 'none' keeps everything. harness-blocked are killable only "
             "with a leak detector, call-pattern only by observing the calls "
             "made on the neighbouring BIO".format("|".join(mutants.DROPPABLE)),
    )
    mt.add_argument(
        "--cluster",
        default=None,
        help="restrict to one enclosing function, the unit Arm 2 runs on",
    )
    mt.add_argument(
        "--format",
        choices=("block", "table", "json"),
        default="block",
        help="block: the prompt text; table: the triage view; json: the data",
    )
    mt.add_argument(
        "--list-clusters",
        action="store_true",
        help="just the cluster names and sizes",
    )

    sc = sub.add_parser(
        "scenarios",
        help="Arm 1 stage 1: ask the model what to test, before any test exists",
    )
    sc.add_argument("--source", default=DEFAULT_SOURCE)
    sc.add_argument(
        "--seeds", default="1-50",
        help="one call, and so one scenario, per seed (e.g. 1-50 or 1,3,5)")
    sc.add_argument(
        "--temperature", type=float, default=None,
        help="default: unset, i.e. whatever the endpoint does on its own")
    sc.add_argument("--profile", default=None)
    sc.add_argument("--model", default=None)
    sc.add_argument("--api-url", default=None)
    sc.add_argument("--out", default=None, help="where to write the record")

    ar = sub.add_parser("arm", help="run Arm 1 stage 2, or Arm 2")
    ar.add_argument("arm", choices=("1", "2"))
    ar.add_argument("config", help="experiment config JSON")
    ar.add_argument("--scenarios", default=None, help="arm 1: the stage-1 record")
    ar.add_argument(
        "--bundle",
        action="store_true",
        help="arm 1 only: hand a seed's whole scenario set to one generation "
             "(Arm 1b) instead of one generation per scenario. Trades "
             "per-scenario attribution for more assertions per run",
    )
    ar.add_argument("--triage", default=None, help="arm 2: the triage JSON")
    ar.add_argument(
        "--drop", default="equivalent",
        help="arm 2: triage classes to exclude, comma-separated; 'none' keeps all")
    ar.add_argument("--seeds", default="1-10", help="arm 2: seeds per cluster")
    ar.add_argument(
        "--cluster", action="append", default=[],
        help="arm 2: run only these clusters, by function name; repeatable. "
             "Use with --targets-from to finish a cell an outage cut short")
    ar.add_argument(
        "--targets-from", default=None,
        help="arm 2: take the clusters and their targets from a snapshot "
             "written by --save-targets, instead of re-planning them. A "
             "re-plan after any mutation pass can hand a cluster a different "
             "set, which would make the runs a different cell")
    ar.add_argument(
        "--save-targets", default=None,
        help="arm 2: write the planned clusters and targets here")
    ar.add_argument(
        "--prefix", default=None,
        help="leading component of every run name, replacing the arm's default "
             "(a1/a1b/a2). Give a new cell its own prefix so its tests are "
             "distinguishable in test/ from an earlier run of the same arm")
    ar.add_argument(
        "--cell", default=None,
        help="the label these runs carry in the arm tables. Without it a "
             "re-run of an arm pools with the earlier one, which averages two "
             "different experiments")
    ar.add_argument(
        "--temperature", type=float, default=None,
        help="default: unset, i.e. whatever the endpoint does on its own")
    ar.add_argument("--limit", type=int, default=None)
    ar.add_argument("--no-register", action="store_true")
    ar.add_argument(
        "--dry-run", action="store_true",
        help="print what would run; call no model, write nothing")

    arp = sub.add_parser(
        "arms-report",
        help="join generations to mutation reports and print the arm tables",
    )
    arp.add_argument("--source", default=DEFAULT_SOURCE)
    arp.add_argument("--out-dir", default=None)
    arp.add_argument(
        "--all-sources", action="store_true",
        help="do not restrict rows to --source; only useful for a global count")
    arp.add_argument(
        "--rows", default=None,
        help="also write the joined per-run table here as JSONL")
    arp.add_argument(
        "--arm", action="append", default=[],
        help="restrict to these arms, repeatable")
    arp.add_argument(
        "--scenarios", default=None,
        help="also print Table 3 from this stage-1 scenario record")
    arp.add_argument(
        "--classification", default=None,
        help="hand classification of those scenarios; Table 3 is reported "
             "from this when given, and from the regex pass otherwise")
    arp.add_argument(
        "--list-scenarios", action="store_true",
        help="print every scenario sentence with the classes it matched, so "
             "the automatic classification can be checked by hand")

    fill = sub.add_parser("fill", help="splice a generated body into a stub")
    fill.add_argument("stub", help="path to the stub .c file")
    fill.add_argument("body", nargs="?", default="-", help="body file, or '-' for stdin")

    return parser


def cmd_context(args: argparse.Namespace) -> None:
    opts = _options_from(args)
    if args.contract_only:
        sys.stdout.write(build_contract_only(opts))
        return
    if not args.source:
        raise ContextError("expected a source file (or --contract-only)")
    sys.stdout.write(build_prompt(args.source, opts))


def cmd_stub(args: argparse.Namespace) -> None:
    source = paths.resolve_under_repo(args.source) if args.source else None
    sys.stdout.write(stub.generate_stub(args.program, args.function, source))


def cmd_mutants(args: argparse.Namespace) -> None:
    source_path = paths.resolve_under_repo(args.source)
    if not source_path.is_file():
        raise mutants.MutantError("source not found: {}".format(source_path))

    if args.report:
        report = paths.resolve_under_repo(args.report)
        chosen = mutants.survivors(report, args.source)
        covered, runs = None, None
        # Mull's line numbers refer to the source it saw, so prefer that copy.
        text = mutants.report_source(report, args.source) or source_path.read_text()
    else:
        reports, missing = mutants.corpus_reports(
            mutation.load_results(latest_only=True))
        if missing:
            print(">> [Mutants] {} recorded run(s) have no report on disk and "
                  "are NOT in this denominator: {}{}".format(
                      len(missing), ", ".join(sorted(missing)[:3]),
                      ", ..." if len(missing) > 3 else ""),
                  file=sys.stderr)
        if not reports:
            raise mutants.MutantError(
                "no recorded reports under {}; run `mutate` first, or pass "
                "--report".format(mutation.MUTATION_DIR))
        chosen, covered = mutants.never_killed(reports, args.source)
        runs = len(reports)
        text = mutants.report_source(reports[0], args.source) or source_path.read_text()

    if args.triage:
        triage = mutants.load_triage(paths.resolve_under_repo(args.triage))
        before = len(chosen)
        drop = [d.strip() for d in args.drop.split(",") if d.strip()]
        if drop == ["none"]:
            drop = []
        bad = sorted(set(drop) - set(mutants.DROPPABLE))
        if bad:
            raise mutants.MutantError("unknown --drop class(es): {}".format(
                ", ".join(bad)))
        chosen, unknown = mutants.apply_triage(chosen, triage, drop)
        if unknown:
            print(">> [Mutants] {} mutant(s) are not in the triage and were "
                  "kept; re-run the classification:\n   {}".format(
                      len(unknown), "\n   ".join(unknown)), file=sys.stderr)
        if before != len(chosen):
            print(">> [Mutants] triage dropped {} mutant(s) ({}); denominator "
                  "is {}, not {}".format(before - len(chosen), ", ".join(drop),
                                         len(chosen), before), file=sys.stderr)

    clusters = mutants.cluster(chosen, mutants.find_functions(text))
    if args.cluster:
        clusters = [c for c in clusters if c.function == args.cluster]
        if not clusters:
            raise mutants.MutantError("no surviving mutants in cluster {!r}".format(
                args.cluster))

    if args.list_clusters:
        for group in clusters:
            print("{:<20} {:>3} mutant(s)   lines {}-{}".format(
                group.function, len(group.mutants), group.start, group.end))
        return

    if args.format == "json":
        sys.stdout.write(mutants.to_json(clusters, text, covered))
    elif args.format == "table":
        sys.stdout.write(mutants.format_table(clusters, text, covered, runs) + "\n")
    else:
        chosen = [m for group in clusters for m in group.mutants]
        sys.stdout.write(mutants.format_block(chosen, text, args.source))


def _seeds(spec: str) -> list:
    """"1-10" or "1,3,5" -> a list of ints."""
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part.lstrip("-"):
            lo, _, hi = part.partition("-")
            out.extend(range(int(lo), int(hi) + 1))
        else:
            out.append(int(part))
    if not out:
        raise arms.ArmError("no seeds in {!r}".format(spec))
    return out


def cmd_scenarios(args: argparse.Namespace) -> None:
    out = (paths.resolve_under_repo(args.out) if args.out
           else arms.ARMS_DIR / "scenarios_{}.json".format(
               Path(args.source).stem))
    record = arms.generate_scenarios(
        args.source, _seeds(args.seeds),
        profile=args.profile, model=args.model, api_url=args.api_url,
        temperature=args.temperature, out_path=out)
    ok = [s for s in record["samples"] if s["ok"]]
    distinct = len({s["scenario"].lower().rstrip(".") for s in ok})
    print("{}/{} call(s) ok; {} distinct scenario(s); written to {}".format(
        len(ok), len(record["samples"]), distinct, out))


def cmd_arm(args: argparse.Namespace) -> None:
    config = experiment.load_config(args.config)

    if args.arm == "1":
        if not args.scenarios:
            raise arms.ArmError("arm 1 needs --scenarios (run `scenarios` first)")
        scenarios = arms.load_scenarios(paths.resolve_under_repo(args.scenarios))
        samples = [s for s in scenarios["samples"] if s.get("scenarios")]
        jobs = (len(samples) if args.bundle
                else sum(len(s["scenarios"]) for s in samples))
        if args.dry_run:
            print("arm {}: {} generation(s) from {} scenario call(s)".format(
                "1b" if args.bundle else "1", jobs, len(samples)))
            print("prefix {}, cell {}".format(
                args.prefix or ("a1b" if args.bundle else "a1"),
                args.cell or "(none -- pools with the other runs of this arm)"))
            if args.bundle and samples:
                print("\nexample bundled task (seed {}):\n".format(samples[0]["seed"]))
                print(arms.bundle_task(samples[0]["scenarios"]))
            return
        results = arms.run_arm1(config, scenarios, temperature=args.temperature,
                                limit=args.limit, register=not args.no_register,
                                bundle=args.bundle, prefix=args.prefix,
                                cell=args.cell)
    else:
        triage = paths.resolve_under_repo(args.triage) if args.triage else None
        drop = [d.strip() for d in args.drop.split(",") if d.strip()]
        if drop == ["none"]:
            drop = []
        if args.targets_from:
            clusters = arms.load_target_snapshot(
                paths.resolve_under_repo(args.targets_from))
            text = arms.arm2_source_text(config["source"])
        else:
            clusters, text = arms.arm2_clusters(config["source"], triage, drop)
        if args.cluster:
            wanted = set(args.cluster)
            unknown = wanted - {c.function for c in clusters}
            if unknown:
                raise arms.ArmError("no such cluster(s): {}".format(
                    ", ".join(sorted(unknown))))
            clusters = [c for c in clusters if c.function in wanted]
        if args.save_targets:
            path = arms.save_target_snapshot(
                clusters, paths.resolve_under_repo(args.save_targets),
                config["source"], drop)
            print("wrote target snapshot to {}".format(path))
        seeds = _seeds(args.seeds)
        if args.dry_run:
            for group in clusters:
                print("{:<18} {:>3} target(s) x {} seed(s)  {}".format(
                    group.function, len(group.mutants), len(seeds),
                    ", ".join("L{}".format(m.line) for m in group.mutants)))
            print("arm 2: {} generation(s)".format(len(clusters) * len(seeds)))
            print("prefix {}, cell {}".format(
                args.prefix or "a2",
                args.cell or "(none -- pools with the other runs of this arm)"))
            return
        results = arms.run_arm2(config, clusters, text, seeds,
                                temperature=args.temperature,
                                register=not args.no_register, limit=args.limit,
                                prefix=args.prefix, cell=args.cell)

    ok = sum(1 for r in results if r.get("ok"))
    print("arm {}: {}/{} generation(s) succeeded".format(args.arm, ok, len(results)))
    for record in results:
        if not record.get("ok"):
            print("  FAILED {}: {}".format(record["name"], record["error"]))


def cmd_arms_report(args: argparse.Namespace) -> None:
    rows = analysis.join(args.out_dir, args.source,
                         only_source=not args.all_sources)
    if args.arm:
        # Cells are labelled strings ("1 (1/call, L50)"), so --arm 1 has to
        # mean "every cell of arm 1" rather than an exact match.
        wanted = [a.strip() for a in args.arm]
        rows = [r for r in rows
                if any(analysis.in_arm(r["arm"], a) for a in wanted)]
    if args.rows:
        path = analysis.write_rows(rows, paths.resolve_under_repo(args.rows))
        print("wrote {} row(s) to {}\n".format(len(rows), path))

    outage = [r for r in rows if not r.get("reached_model", True)]
    if outage:
        from collections import Counter as _Counter
        print("{} attempt(s) never reached the model and are not in any "
              "denominator below: {}".format(
                  len(outage), ", ".join(
                      "{} x{}".format(arm, n) for arm, n
                      in sorted(_Counter(str(r["arm"]) for r in outage).items()))))
        print()

    print("Table 1 - arm comparison ({})".format(args.source))
    print(analysis.table1(rows, args.source))
    print()
    print("Table 2 - Arm 2 per cluster: hallucinated coverage")
    print(analysis.table2(rows))
    print()
    print("Defect mix")
    print(analysis.defect_mix(rows))

    if args.scenarios:
        scenarios = arms.load_scenarios(paths.resolve_under_repo(args.scenarios))
        print()
        print("Table 3 - Arm 1 scenario coverage")
        if args.classification:
            import json as _json
            hand = _json.loads(
                paths.resolve_under_repo(args.classification).read_text())
            print(analysis.table3_hand(hand, scenarios))
        else:
            print(analysis.table3(scenarios))
        if args.list_scenarios:
            print()
            print("Every scenario sentence, with the classes it matched:")
            for sample in scenarios.get("samples", []):
                for i, text in enumerate(sample.get("scenarios") or [], 1):
                    classes = analysis.classify_scenario(text)
                    print("  s{}.{:<2} {}".format(sample["seed"], i, text))
                    print("        -> {}".format(
                        ", ".join(classes) if classes else "(no class)"))


def cmd_fill(args: argparse.Namespace) -> None:
    stub.fill_stub(paths.resolve_under_repo(args.stub), stub.read_body(args.body))


def cmd_generate(args: argparse.Namespace) -> None:
    started = time.monotonic()

    # Bare `generate` with no arguments runs the default AES-256 scenario.
    if args.source is None:
        backends.log(">> [Info] No context arguments provided. Applying default AES-256 snippet task...")
        args.source = DEFAULT_SOURCE
        args.snippet = True
        args.task = args.task or DEFAULT_TASK
        args.into = args.into or DEFAULT_INTO

    # In snippet mode the model is filling a specific file, so show it that
    # file: without it the model cannot know which headers exist or what the
    # function is called, and guesses wrong.
    if args.snippet and not args.stub and args.into:
        args.stub = args.into

    prompt = build_prompt(args.source, _options_from(args))
    endpoint = backends.resolve_profile(args.profile, args.api_url, args.model)
    result = backends.run_prompt(prompt, endpoint, _params_from(args))

    if args.into:
        target = paths.resolve_under_repo(args.into)
        stub.fill_stub(target, result)
        backends.log(">> [Info] Wrote generated body into {}".format(target))
    else:
        sys.stdout.write(result)

    backends.log(">> [Timing] Completed in {:.1f}s".format(time.monotonic() - started))


def cmd_experiment(args: argparse.Namespace) -> None:
    config = experiment.load_config(args.config)
    for key in ("source", "task", "test_fn", "prefix", "model", "profile",
                "api_url", "repeats", "sleep"):
        value = getattr(args, key, None)
        if value is not None:
            config[key] = value

    results = experiment.run_experiment(
        config,
        grid_override=experiment.parse_grid_override(args.grid),
        dry_run=args.dry_run,
        limit=args.limit,
        register=not args.no_register,
        out_dir=args.out_dir,
    )

    if args.dry_run:
        for record in results:
            print("{:>3}  {}".format(record["index"], record["name"]))
        print("{} run(s) planned; nothing was sent or written".format(len(results)))
        return

    failed = [r for r in results if not r.get("ok")]
    for record in failed:
        print("FAILED {}: {}".format(record["name"], record["error"]), file=sys.stderr)
    if failed:
        raise BackendError("{}/{} run(s) failed".format(len(failed), len(results)))


def cmd_runs(args: argparse.Namespace) -> None:
    records = experiment.list_runs(args.out_dir)
    if not records:
        print("no runs under {}".format(args.out_dir or experiment.OUT_DIR))
        return
    for record in records:
        print("{}  {:>4}  {}".format(
            "????" if record.get("_incomplete") else ("ok  " if record.get("ok") else "FAIL"),
            "{}s".format(record.get("duration_s") or "?"),
            record["name"]))
    print("{} run(s) under {}".format(len(records), args.out_dir or experiment.OUT_DIR))


def cmd_prune(args: argparse.Namespace) -> None:
    if not args.names and not args.all and not args.failed:
        raise experiment.ExperimentError("prune needs run names, --all, or --failed")

    removed = experiment.prune(
        args.names,
        all_runs=args.all,
        failed_only=args.failed,
        dry_run=args.dry_run,
        keep_index=args.keep_index,
        out_root=args.out_dir,
    )
    if args.dry_run:
        print("{} run(s) would be deleted; nothing was touched".format(len(removed)))
    elif removed:
        print("deleted {} run(s); reconfigure happens on the next compile".format(len(removed)))


def cmd_mutate(args: argparse.Namespace) -> None:
    if not args.names and not args.all:
        raise mutation.MutationError("mutate needs run names or --all")

    results = mutation.run_batch(
        args.names,
        all_runs=args.all,
        out_dir=args.out_dir,
        configure=not args.no_configure,
        build=not args.no_build,
        rerun=args.rerun,
        source=args.source or DEFAULT_SOURCE,
    )
    if not results:
        return
    print()
    print(mutation.table(results))
    failed = [r for r in results if not r.get("ok")]
    print("{}/{} run(s) scored; appended to {} and {}".format(
        len(results) - len(failed), len(results),
        mutation.RESULTS.name, mutation.RESULTS_CSV))
    if failed:
        raise mutation.MutationError("{} run(s) failed".format(len(failed)))


def cmd_mutation_report(args: argparse.Namespace) -> None:
    if args.rebuild_csv:
        path = mutation.rebuild_csv()
        print("rebuilt {} with {} test(s), newest run each".format(
            path, len(mutation.load_results(latest_only=True))))
        return

    if args.survivors:
        record = next((r for r in mutation.load_results()
                       if r["name"] == args.survivors), None)
        if not record or not record.get("report"):
            raise mutation.MutationError("no report for {}".format(args.survivors))
        survivors = mutation.surviving_lines(
            paths.REPO_ROOT / record["report"], record.get("source"))
        for mutant in survivors:
            print("{}:{}  {} -> {!r}".format(
                mutant["file"], mutant["line"], mutant["mutator"], mutant["replacement"]))
        print("{} surviving mutant(s)".format(len(survivors)))
        return

    if args.csv:
        # The CSV is appended to as runs finish, so it is already the record;
        # printing it beats re-deriving one and risking a second copy.
        if not mutation.RESULTS_CSV.is_file():
            print("no CSV yet at {} (run `mutate`, or --rebuild-csv)".format(
                mutation.RESULTS_CSV))
            return
        sys.stdout.write(mutation.RESULTS_CSV.read_text())
        return

    records = mutation.load_results(latest_only=not args.history)
    if not records:
        print("no results under {}".format(mutation.MUTATION_DIR))
        return
    sys.stdout.write(mutation.table(records) + "\n")


COMMANDS = {
    "generate": cmd_generate,
    "experiment": cmd_experiment,
    "runs": cmd_runs,
    "prune": cmd_prune,
    "mutate": cmd_mutate,
    "mutation-report": cmd_mutation_report,
    "context": cmd_context,
    "mutants": cmd_mutants,
    "scenarios": cmd_scenarios,
    "arm": cmd_arm,
    "arms-report": cmd_arms_report,
    "stub": cmd_stub,
    "fill": cmd_fill,
}


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        COMMANDS[args.command](args)
    except (ContextError, BackendError, StubError, experiment.ExperimentError,
            mutation.MutationError, mutants.MutantError,
            arms.ArmError, buildinfo.BuildInfoError) as exc:
        print("llm_test: {}".format(exc), file=sys.stderr)
        return 1
    return 0
