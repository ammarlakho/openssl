"""Directory layout for the thesis scripts."""

from pathlib import Path

# .../openssl/thesis-work/scripts/llmtest/paths.py
#      [3]      [2]         [1]     [0]
_HERE = Path(__file__).resolve()

REPO_ROOT = _HERE.parents[3]
THESIS_ROOT = _HERE.parents[2]
SCRIPTS_ROOT = _HERE.parents[1]

DOCS = THESIS_ROOT / "docs"
CONTRACT = DOCS / "llm-openssl-test-contract.md"
SNIPPET_CONTRACT = DOCS / "llm-openssl-test-snippet.md"

TEST_DIR = REPO_ROOT / "test"
ENV_FILE = THESIS_ROOT / "llm-models.env"


def resolve_under_repo(path: str) -> Path:
    """Resolve a possibly-relative path against the repo root.

    Lets the scripts behave the same regardless of the caller's cwd.
    """
    p = Path(path)
    return p if p.is_absolute() else REPO_ROOT / p
