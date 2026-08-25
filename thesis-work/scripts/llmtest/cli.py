"""Command line entry point. See ../llm_test.py.

Subcommands:
  generate  assemble a prompt, run a model, print or splice the result
  context   print the assembled prompt without calling a model
  stub      print a fresh test .c skeleton
  fill      splice a generated body into an existing stub
"""

import argparse
import sys
import time
from pathlib import Path

from . import backends, paths, stub
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
    return parser


def _params_from(args: argparse.Namespace) -> GenParams:
    return GenParams(
        temperature=args.temperature,
        top_p=args.top_p,
        seed=args.seed,
        max_tokens=args.max_tokens,
        reasoning_effort=args.reasoning_effort,
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


COMMANDS = {
    "generate": cmd_generate,
    "context": cmd_context,
    "stub": cmd_stub,
    "fill": cmd_fill,
}


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        COMMANDS[args.command](args)
    except (ContextError, BackendError, StubError) as exc:
        print("llm_test: {}".format(exc), file=sys.stderr)
        return 1
    return 0
