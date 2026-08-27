"""Command line entry point. See ../llm_test.py.

Subcommands:
  generate  assemble a prompt, run a model, print or splice the result
  context   print the assembled prompt without calling a model
  stub      print a fresh test .c skeleton
  fill      splice a generated body into an existing stub
  experiment  run a grid of sampling parameters, one saved test per point
  mutate    run Mull over generated tests and record the scores
  mutation-report  print the recorded scores as a table or CSV
"""

import argparse
import sys
import time
from pathlib import Path

from . import backends, buildinfo, experiment, mutation, paths, stub
from .context import ContextError, ContextOptions, build_contract_only, build_prompt
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
    "stub": cmd_stub,
    "fill": cmd_fill,
}


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        COMMANDS[args.command](args)
    except (ContextError, BackendError, StubError, experiment.ExperimentError,
            mutation.MutationError, buildinfo.BuildInfoError) as exc:
        print("llm_test: {}".format(exc), file=sys.stderr)
        return 1
    return 0
