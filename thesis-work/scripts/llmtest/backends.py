"""Send a prompt to a model over an OpenAI-compatible chat-completions API.

Uses urllib and the standard library, no external dependencies.
"""

import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional

from . import paths

DEFAULT_PROFILE = "gptoss"
REQUEST_TIMEOUT = 600


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
        log(">> [Warn] finish_reason={} — output may be truncated".format(finish))


# --------------------------------------------------------------------------
# Remote OpenAI-compatible endpoint
# --------------------------------------------------------------------------

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
):
    """Work out which endpoint, model and key to talk to.

    Precedence, highest first: explicit CLI arguments, the real environment,
    then llm-models.env. A profile named `foo` reads FOO_API_URL / FOO_MODEL /
    FOO_API_KEY.
    """
    file_env = load_env_file()

    def lookup(key: str) -> Optional[str]:
        return os.environ.get(key) or file_env.get(key)

    profile = profile or lookup("LLM_PROFILE") or DEFAULT_PROFILE
    prefix = profile.upper()

    api_url = api_url or lookup("API_URL") or lookup("{}_API_URL".format(prefix))
    model = model or lookup("LLM_MODEL") or lookup("{}_MODEL".format(prefix))
    api_key = lookup("{}_API_KEY".format(prefix)) or lookup("API_KEY")

    if not api_url:
        raise BackendError(
            "API_URL is not set for profile '{}'. Set API_URL or {}_API_URL "
            "in {} or the environment.".format(profile, prefix, paths.ENV_FILE)
        )
    if not model:
        raise BackendError(
            "model is not set for profile '{}'. Set LLM_MODEL or {}_MODEL "
            "in {} or the environment.".format(profile, prefix, paths.ENV_FILE)
        )
    return profile, api_url, model, api_key


def run_remote(
    prompt: str,
    profile: Optional[str] = None,
    api_url: Optional[str] = None,
    model: Optional[str] = None,
    params: Optional[GenParams] = None,
) -> str:
    """POST `prompt` to a chat-completions endpoint and return the reply."""
    profile, api_url, model, api_key = resolve_profile(profile, api_url, model)
    params = params or GenParams()

    body: Dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }
    # Absent knobs are left out entirely rather than sent as null, since some
    # OpenAI-compatible servers reject unknown or null fields.
    body.update(params.as_dict())

    headers = {}
    if api_key:
        headers["Authorization"] = "Bearer {}".format(api_key)

    log(
        ">> [Info] Querying remote LLM ({} @ {}) [{}]...".format(
            model, api_url, params.describe()
        )
    )
    payload = _post_json(api_url, body, headers)

    log(
        ">> [API Log] Profile: {} | Model: {} | Fingerprint: {}".format(
            profile,
            payload.get("model", "N/A"),
            payload.get("system_fingerprint", "N/A"),
        )
    )
    _log_usage(payload)
    return _extract_content(payload)
