"""Send a prompt to a model: local Ollama, or a remote OpenAI-compatible API.

Uses urllib and the standard library, no external dependencies.
"""

import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Dict, Optional

from . import paths

DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:7b"
DEFAULT_PROFILE = "gptoss"
REQUEST_TIMEOUT = 600


class BackendError(Exception):
    """A model could not be reached, or answered with an error."""


def log(message: str) -> None:
    print(message, file=sys.stderr)


# --------------------------------------------------------------------------
# Local Ollama
# --------------------------------------------------------------------------

def run_ollama(prompt: str, model: Optional[str] = None) -> str:
    """Pipe `prompt` through `ollama run` and return the model's reply."""
    model = model or os.environ.get("OLLAMA_MODEL") or DEFAULT_OLLAMA_MODEL

    if shutil.which("ollama") is None:
        raise BackendError("'ollama' not found in PATH")

    log(">> [Info] Querying local Ollama ({})...".format(model))
    proc = subprocess.run(
        ["ollama", "run", model, "--keepalive", "0"],
        input=prompt,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise BackendError(
            "ollama exited {}: {}".format(proc.returncode, proc.stderr.strip())
        )
    return proc.stdout


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
    """Work out which endpoint and model to talk to.

    Precedence, highest first: explicit CLI arguments, the real environment,
    then llm-models.env. A profile named `foo` reads FOO_API_URL / FOO_MODEL.
    """
    file_env = load_env_file()

    def lookup(key: str) -> Optional[str]:
        return os.environ.get(key) or file_env.get(key)

    profile = profile or lookup("LLM_PROFILE") or DEFAULT_PROFILE
    prefix = profile.upper()

    api_url = api_url or lookup("API_URL") or lookup("{}_API_URL".format(prefix))
    model = model or lookup("LLM_MODEL") or lookup("{}_MODEL".format(prefix))

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
    return profile, api_url, model


def _extract_content(payload: dict) -> str:
    """Pull the reply text out of an OpenAI- or Ollama-shaped response."""
    choices = payload.get("choices")
    if choices:
        return choices[0].get("message", {}).get("content", "")
    # Ollama's native /api/chat uses a flat "message" object instead.
    message = payload.get("message")
    if isinstance(message, dict):
        return message.get("content", "")
    raise BackendError("no content in response: {}".format(json.dumps(payload)[:500]))


def run_remote(
    prompt: str,
    profile: Optional[str] = None,
    api_url: Optional[str] = None,
    model: Optional[str] = None,
) -> str:
    """POST `prompt` to a chat-completions endpoint and return the reply."""
    profile, api_url, model = resolve_profile(profile, api_url, model)

    body = json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
    ).encode()

    request = urllib.request.Request(
        api_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    log(">> [Info] Querying remote LLM ({} @ {})...".format(model, api_url))
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            raw = response.read().decode()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:500]
        raise BackendError("HTTP {} from {}: {}".format(exc.code, api_url, detail))
    except urllib.error.URLError as exc:
        raise BackendError("could not reach {}: {}".format(api_url, exc.reason))

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise BackendError("response was not JSON: {}".format(raw[:500]))

    error = payload.get("error")
    if error:
        message = error.get("message") if isinstance(error, dict) else error
        raise BackendError("API error: {}".format(message))

    log(
        ">> [API Log] Profile: {} | Model: {} | Fingerprint: {}".format(
            profile,
            payload.get("model", "N/A"),
            payload.get("system_fingerprint", "N/A"),
        )
    )
    return _extract_content(payload)
