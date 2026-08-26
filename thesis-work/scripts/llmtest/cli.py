"""Command line entry point. See ../llm_test.py.

Subcommands:
  generate  assemble a prompt, run a model, print or splice the result
  context   print the assembled prompt without calling a model
  stub      print a fresh test .c skeleton
  fill      splice a generated body into an existing stub
  sweep     run a grid of sampling parameters, one saved test per point
"""

import argparse
import sys
import time
from pathlib import Path

from . import backends, buildinfo, paths, stub, sweep
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
        choices=("low", "medium", "high"),
        default=None,
        help="reasoning models (gpt-oss); ignored by servers that do not support it",
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

    sw = sub.add_parser(
        "sweep",
        help="run a grid of sampling parameters, saving one test per point",
    )
    sw.add_argument("config", nargs="?", help="sweep config JSON (see thesis-work/sweeps/)")
    sw.add_argument(
        "--grid",
        action="append",
        default=[],
        metavar="AXIS=V1,V2",
        help="override one grid axis, repeatable "
             "(e.g. --grid temperature=0.2,0.8 --grid seed=1,2,3)",
    )
    sw.add_argument("--source", help="override the source under test")
    sw.add_argument("--task", help="override the scenario description")
    sw.add_argument("--test-fn", help="override the test function name")
    sw.add_argument("--prefix", help="override the leading name component")
    sw.add_argument("--model", help="override the model name")
    sw.add_argument("--profile", help="endpoint profile name")
    sw.add_argument("--api-url", help="endpoint URL, overriding the profile")
    sw.add_argument("--repeats", type=int, default=None, help="runs per grid point")
    sw.add_argument("--sleep", type=float, default=None, help="seconds between calls")
    sw.add_argument("--limit", type=int, default=None, help="stop after N runs")
    sw.add_argument("--out-dir", default=None, help="override test/generated")
    sw.add_argument(
        "--no-register",
        action="store_true",
        help="skip the test/build.info entry for each generated test",
    )
    sw.add_argument(
        "--dry-run",
        action="store_true",
        help="print the planned runs and their names; call no model, write nothing",
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
    result = backends.run_remote(
        prompt, args.profile, args.api_url, args.model, _params_from(args)
    )

    if args.into:
        target = paths.resolve_under_repo(args.into)
        stub.fill_stub(target, result)
        backends.log(">> [Info] Wrote generated body into {}".format(target))
    else:
        sys.stdout.write(result)

    backends.log(">> [Timing] Completed in {:.1f}s".format(time.monotonic() - started))


def cmd_sweep(args: argparse.Namespace) -> None:
    config = sweep.load_config(args.config)
    for key in ("source", "task", "test_fn", "prefix", "model", "profile",
                "api_url", "repeats", "sleep"):
        value = getattr(args, key, None)
        if value is not None:
            config[key] = value

    results = sweep.run_sweep(
        config,
        grid_override=sweep.parse_grid_override(args.grid),
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


COMMANDS = {
    "generate": cmd_generate,
    "sweep": cmd_sweep,
    "context": cmd_context,
    "stub": cmd_stub,
    "fill": cmd_fill,
}


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        COMMANDS[args.command](args)
    except (ContextError, BackendError, StubError, sweep.SweepError,
            buildinfo.BuildInfoError) as exc:
        print("llm_test: {}".format(exc), file=sys.stderr)
        return 1
    return 0
