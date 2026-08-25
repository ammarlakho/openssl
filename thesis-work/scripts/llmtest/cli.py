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
from .backends import BackendError
from .stub import StubError

# Applied by `generate` when the caller passes no context arguments at all.
DEFAULT_TASK = "AES-256 CBC BIO round-trip vs fixed vectors"
DEFAULT_SOURCE = "crypto/evp/bio_enc.c"
DEFAULT_INTO = "test/generated_test.c"
DEFAULT_IMPL_LINES = 400


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
        help="include the whole source file instead of the first --impl-lines",
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
        help="lines of the source file to include (default: 280)",
    )
    parser.add_argument("--refs", type=int, default=None, help="number of reference tests")
    parser.add_argument("--lines", type=int, default=None, help="lines per reference test")
    return parser


def _options_from(args: argparse.Namespace) -> ContextOptions:
    opts = ContextOptions(
        snippet=args.snippet,
        full_source=args.full_source,
        notes=args.notes,
        task=args.task,
        keywords=[k for k in args.keywords.split(",") if k.strip()],
        refs=args.refs,
        lines=args.lines,
    )
    if args.impl_lines is not None:
        opts.impl_lines = args.impl_lines
    return opts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm_test.py",
        description="Generate OpenSSL unit tests with an LLM.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    shared = _context_parser()

    gen = sub.add_parser(
        "generate",
        parents=[shared],
        help="run a model and print or splice the generated test",
    )
    gen.add_argument("source", nargs="?", help="path to the source file under test")
    gen.add_argument(
        "--backend",
        choices=("ollama", "remote"),
        default="remote",
        help="local Ollama or a remote OpenAI-compatible endpoint (default)",
    )
    gen.add_argument("--into", help="stub .c file to splice the result into")
    gen.add_argument("--model", help="override the model name")
    gen.add_argument("--profile", help="remote profile name (default: gptoss)")
    gen.add_argument("--api-url", help="remote endpoint URL, overriding the profile")

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
    sys.stdout.write(stub.generate_stub(args.program, args.function))


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
        args.impl_lines = args.impl_lines or DEFAULT_IMPL_LINES
        args.into = args.into or DEFAULT_INTO

    prompt = build_prompt(args.source, _options_from(args))

    if args.backend == "ollama":
        result = backends.run_ollama(prompt, args.model)
    else:
        result = backends.run_remote(prompt, args.profile, args.api_url, args.model)

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
