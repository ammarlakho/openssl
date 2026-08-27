"""Send a prompt to a model and return its reply.

Two kinds of backend sit behind one interface:

    http  an OpenAI-compatible /v1/chat/completions endpoint (gpt-oss, gemma)
    cli   the Claude Code CLI, which speaks no HTTP and needs no API key

`resolve_profile` decides which and returns an Endpoint; `run_prompt` takes that
Endpoint and does the right thing. Callers never branch on the profile name, so
`experiment` can sweep a Claude profile the same way it sweeps a vLLM one.

Uses urllib and the standard library, no external dependencies.
"""

import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional, Tuple

from . import paths

DEFAULT_PROFILE = "gptoss"
REQUEST_TIMEOUT = 600

HTTP_KIND = "http"
CLI_KIND = "cli"


class BackendError(Exception):
    """A model could not be reached, or answered with an error."""


def log(message: str) -> None:
    print(message, file=sys.stderr)


@dataclass
class GenParams:
    """Sampling knobs. Every field is optional: None means "server default".

    Kept as one object so an experiment can vary decoding without touching the call
    sites, and so the exact settings behind a generated test can be recorded.
    """

    temperature: Optional[float] = None
    top_p: Optional[float] = None
    seed: Optional[int] = None
    max_tokens: Optional[int] = None
    # gpt-oss and other reasoning models: "low" | "medium" | "high".
    # The Claude CLI spells the same idea --effort and accepts two more levels.
    reasoning_effort: Optional[str] = None
    # Repetition control. Two spellings, because the two servers in use do not
    # agree on one:
    #   frequency_penalty  -- the OpenAI field. Ollama's /v1 layer maps it onto
    #                         llama.cpp's repeat_penalty; vLLM implements it
    #                         natively. Portable, so prefer it. Range ~[-2, 2],
    #                         0 = off.
    #   repetition_penalty -- vLLM's own multiplicative knob, sent as an extra
    #                         top-level field. Range ~[1.0, 2.0], 1.0 = off.
    #                         Ignored by servers that do not know it.
    # There is no "repeat_penalty" field on either OpenAI-compatible endpoint:
    # that name belongs to llama.cpp / Ollama's native /api/generate options.
    frequency_penalty: Optional[float] = None
    presence_penalty: Optional[float] = None
    repetition_penalty: Optional[float] = None

    def as_dict(self) -> Dict[str, Any]:
        """Only the fields that were actually set."""
        return {k: v for k, v in asdict(self).items() if v is not None}

    def describe(self) -> str:
        given = self.as_dict()
        return ", ".join("{}={}".format(k, v) for k, v in sorted(given.items())) or "server defaults"


def _post_json(url: str, body: Dict[str, Any], headers: Dict[str, str]) -> dict:
    """POST a JSON body and return the decoded reply."""
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers=dict(headers, **{"Content-Type": "application/json"}),
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            raw = response.read().decode()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:500]
        raise BackendError("HTTP {} from {}: {}".format(exc.code, url, detail))
    except urllib.error.URLError as exc:
        raise BackendError("could not reach {}: {}".format(url, exc.reason))

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise BackendError("response was not JSON: {}".format(raw[:500]))

    error = payload.get("error")
    if error:
        message = error.get("message") if isinstance(error, dict) else error
        raise BackendError("API error: {}".format(message))
    return payload


def _extract_content(payload: dict) -> str:
    """Pull the reply text out of a chat-completions response."""
    choices = payload.get("choices")
    if choices:
        message = choices[0].get("message", {})
    else:
        # Some servers reply with a flat "message" object instead.
        message = payload.get("message")

    if not isinstance(message, dict):
        raise BackendError("no content in response: {}".format(json.dumps(payload)[:500]))

    content = (message.get("content") or "").strip()
    if content:
        return message["content"]

    # Reasoning models can put everything in a separate channel and leave
    # content empty. Splicing that silently would look like a model failure,
    # so say what happened instead.
    if message.get("reasoning_content") or message.get("reasoning"):
        raise BackendError(
            "model returned reasoning but empty content; the endpoint is "
            "putting the answer in 'reasoning_content'. Lower "
            "--reasoning-effort or raise --max-tokens."
        )
    raise BackendError("model returned empty content: {}".format(json.dumps(payload)[:500]))


def _log_usage(payload: dict) -> None:
    usage = payload.get("usage") or {}
    if usage:
        log(
            ">> [Usage] prompt={} completion={} total={}".format(
                usage.get("prompt_tokens", "?"),
                usage.get("completion_tokens", "?"),
                usage.get("total_tokens", "?"),
            )
        )
    finish = (payload.get("choices") or [{}])[0].get("finish_reason")
    if finish and finish not in ("stop", "eos"):
        log(">> [Warn] finish_reason={} -- output may be truncated".format(finish))


# --------------------------------------------------------------------------
# Claude Code CLI backend
# --------------------------------------------------------------------------
#
# `claude -p` runs one headless turn against the logged-in Claude subscription,
# so it needs no ANTHROPIC_API_KEY and no API_URL -- which is why the profile
# cannot go through the URL-and-key resolution the HTTP profiles use.
#
# It is an agent harness rather than a raw completions endpoint, so the flags in
# run_claude_cli strip it back to a plain one-shot chat: no tools, no settings /
# skills / MCP pickup, no session written to disk, and a system prompt we choose
# instead of the coding-agent one. The call also runs in an empty scratch
# directory rather than the repo, because the CLI picks up CLAUDE.md, project
# settings and auto-memory from its cwd -- inside the repo that silently adds
# ~200 tokens of unrelated context to every prompt, which is exactly the kind of
# uncontrolled variable an experiment must not carry.
#
# What it cannot do: temperature, top_p, seed and the repetition penalties do
# not exist on this path. Only the model and the reasoning effort are
# selectable, so decoding sweeps have to run against an HTTP endpoint instead.

CLI_PROFILES = ("claude",)
# `claude --model` takes an alias or a full id; the alias keeps the run names
# readable. Override with CLAUDE_MODEL in llm-models.env.
CLI_DEFAULT_MODEL = "sonnet"
CLI_SYSTEM_PROMPT = (
    "You are a helpful assistant. Answer the user's request directly. "
    "Do not ask questions and do not explain what you are about to do."
)
# --effort accepts two levels beyond the three the OpenAI-compatible servers
# know.
CLI_EFFORTS = ("low", "medium", "high", "xhigh", "max")
# GenParams fields the CLI cannot honour. Never dropped in silence: `generate`
# warns, and `experiment` refuses outright, so a sweep is never recorded under
# settings that were never applied.
CLI_UNSUPPORTED = (
    "temperature",
    "top_p",
    "seed",
    "max_tokens",
    "frequency_penalty",
    "presence_penalty",
    "repetition_penalty",
)


# --------------------------------------------------------------------------
# Profile resolution
# --------------------------------------------------------------------------

@dataclass
class Endpoint:
    """Where a prompt goes, resolved once so every run of a sweep is identical."""

    profile: str
    kind: str                       # HTTP_KIND | CLI_KIND
    model: str                      # never None: run names and results depend on it
    api_url: Optional[str] = None   # CLI_KIND has none
    api_key: Optional[str] = None

    @property
    def unsupported(self) -> Tuple[str, ...]:
        """GenParams fields this backend cannot apply."""
        return CLI_UNSUPPORTED if self.kind == CLI_KIND else ()

    def ignored(self, params: Optional[GenParams]) -> list:
        """The set knobs this backend would quietly drop."""
        given = (params or GenParams()).as_dict()
        return [k for k in self.unsupported if k in given]

    def where(self) -> str:
        return self.api_url if self.kind == HTTP_KIND else "claude CLI"

    def describe(self) -> str:
        return "{} @ {}".format(self.model, self.where())


def load_env_file(path=None) -> Dict[str, str]:
    """Parse a KEY=VALUE env file. Blank values and comments are ignored."""
    path = path or paths.ENV_FILE
    values: Dict[str, str] = {}
    if not path.is_file():
        return values

    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip("'\"")
        if value:
            values[key.strip()] = value
    return values


def resolve_profile(
    profile: Optional[str] = None,
    api_url: Optional[str] = None,
    model: Optional[str] = None,
) -> Endpoint:
    """Work out which backend, model and key to talk to.

    Precedence, highest first: explicit CLI arguments, the real environment,
    then llm-models.env. A profile named `foo` reads FOO_API_URL / FOO_MODEL /
    FOO_API_KEY.

    A profile in CLI_PROFILES resolves to the Claude Code CLI, which has no URL
    and no key, and falls back to CLI_DEFAULT_MODEL rather than demanding one.
    """
    file_env = load_env_file()

    def lookup(key: str) -> Optional[str]:
        return os.environ.get(key) or file_env.get(key)

    profile = profile or lookup("LLM_PROFILE") or DEFAULT_PROFILE
    prefix = profile.upper()
    model = model or lookup("LLM_MODEL") or lookup("{}_MODEL".format(prefix))

    if profile in CLI_PROFILES:
        if api_url:
            raise BackendError(
                "profile '{}' runs the claude CLI, which takes no API URL "
                "(got --api-url {})".format(profile, api_url)
            )
        if not model:
            model = CLI_DEFAULT_MODEL
            log(">> [Info] no {}_MODEL set; using claude --model {}".format(prefix, model))
        return Endpoint(profile=profile, kind=CLI_KIND, model=model)

    api_url = api_url or lookup("API_URL") or lookup("{}_API_URL".format(prefix))
    api_key = lookup("{}_API_KEY".format(prefix)) or lookup("API_KEY")

    if not api_url:
        raise BackendError(
            "API_URL is not set for profile '{}'. Set API_URL or {}_API_URL "
            "in {} or the environment. (CLI profiles, which need no URL: {})".format(
                profile, prefix, paths.ENV_FILE, ", ".join(CLI_PROFILES))
        )
    if not model:
        raise BackendError(
            "model is not set for profile '{}'. Set LLM_MODEL or {}_MODEL "
            "in {} or the environment.".format(profile, prefix, paths.ENV_FILE)
        )
    return Endpoint(profile=profile, kind=HTTP_KIND, model=model,
                    api_url=api_url, api_key=api_key)


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------

def run_prompt(prompt: str, endpoint: Endpoint, params: Optional[GenParams] = None) -> str:
    """Send `prompt` to whichever backend `endpoint` names and return the reply."""
    params = params or GenParams()
    if endpoint.kind == CLI_KIND:
        return run_claude_cli(prompt, endpoint, params)
    return run_http(prompt, endpoint, params)


def run_http(prompt: str, endpoint: Endpoint, params: Optional[GenParams] = None) -> str:
    """POST `prompt` to a chat-completions endpoint and return the reply."""
    params = params or GenParams()

    body: Dict[str, Any] = {
        "model": endpoint.model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }
    # Absent knobs are left out entirely rather than sent as null, since some
    # OpenAI-compatible servers reject unknown or null fields.
    body.update(params.as_dict())

    headers = {}
    if endpoint.api_key:
        headers["Authorization"] = "Bearer {}".format(endpoint.api_key)

    log(">> [Info] Querying remote LLM ({}) [{}]...".format(
        endpoint.describe(), params.describe()))
    payload = _post_json(endpoint.api_url, body, headers)

    log(
        ">> [API Log] Profile: {} | Model: {} | Fingerprint: {}".format(
            endpoint.profile,
            payload.get("model", "N/A"),
            payload.get("system_fingerprint", "N/A"),
        )
    )
    _log_usage(payload)
    return _extract_content(payload)


def run_claude_cli(
    prompt: str,
    endpoint: Endpoint,
    params: Optional[GenParams] = None,
    system_prompt: Optional[str] = None,
) -> str:
    """Run one headless `claude -p` turn and return the reply text."""
    import subprocess

    params = params or GenParams()
    ignored = endpoint.ignored(params)
    if ignored:
        log(">> [Warn] claude CLI ignores: {} (no sampling control on this "
            "backend)".format(", ".join(ignored)))

    effort = params.reasoning_effort
    if effort and effort not in CLI_EFFORTS:
        raise BackendError("claude --effort takes one of {}, got {!r}".format(
            "|".join(CLI_EFFORTS), effort))

    command = [
        "claude",
        "-p", prompt,
        "--model", endpoint.model,
        "--output-format", "json",
        "--system-prompt", system_prompt or CLI_SYSTEM_PROMPT,
        "--tools", "",                 # no file access, no bash, one turn only
        "--setting-sources", "",       # ignore user/project/local settings
        "--disable-slash-commands",
        "--strict-mcp-config",         # with no --mcp-config: no MCP servers
        "--no-session-persistence",
    ]
    if effort:
        command += ["--effort", effort]

    log(">> [Info] Querying claude CLI ({}) [{}]...".format(
        endpoint.describe(), params.describe()))
    # An empty cwd: see the note above on CLAUDE.md and auto-memory pickup.
    try:
        with tempfile.TemporaryDirectory(prefix="llmtest-claude-") as sandbox:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=REQUEST_TIMEOUT,
                cwd=sandbox,
            )
    except FileNotFoundError:
        raise BackendError("`claude` is not on PATH")
    except subprocess.TimeoutExpired:
        raise BackendError("claude CLI timed out after {}s".format(REQUEST_TIMEOUT))

    if completed.returncode != 0:
        raise BackendError(
            "claude CLI exited {}: {}".format(
                completed.returncode, (completed.stderr or completed.stdout)[:500]
            )
        )

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise BackendError("claude CLI output was not JSON: {}".format(completed.stdout[:500]))

    if payload.get("is_error") or payload.get("subtype") != "success":
        raise BackendError("claude CLI error: {}".format(json.dumps(payload)[:500]))

    log(
        ">> [API Log] Profile: {} | Model: {} | Session: {}".format(
            endpoint.profile,
            endpoint.model,
            payload.get("session_id", "N/A"),
        )
    )
    # input_tokens counts only what was not served from the prompt cache, so on
    # its own it reads as a 2-token prompt. The prompt's real size is the sum.
    usage = payload.get("usage") or {}
    prompt_tokens = sum(
        usage.get(k) or 0 for k in
        ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"))
    log(
        ">> [Usage] prompt={} completion={} cost_usd={}".format(
            prompt_tokens,
            usage.get("output_tokens", "?"),
            payload.get("total_cost_usd", "?"),
        )
    )
    stop = payload.get("stop_reason")
    if stop and stop != "end_turn":
        log(">> [Warn] stop_reason={} -- output may be truncated".format(stop))

    reply = (payload.get("result") or "").strip()
    if not reply:
        raise BackendError("claude CLI returned empty content: {}".format(json.dumps(payload)[:500]))
    return reply
