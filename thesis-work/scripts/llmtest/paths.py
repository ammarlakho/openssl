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

# An experiment is a config in, a pile of mutation runs out. Both halves live
# under experiments/; only the configs are committed.
EXPERIMENTS = THESIS_ROOT / "experiments"
CONFIGS = EXPERIMENTS / "configs"
RESULTS_DIR = EXPERIMENTS / "results"
RESULTS_JSONL = RESULTS_DIR / "results.jsonl"
RESULTS_CSV = RESULTS_DIR / "results.csv"

# mull.sh needs it as a repo-relative string, not a Path.
RESULTS_REL = "thesis-work/experiments/results"


def resolve_under_repo(path: str) -> Path:
    """Resolve a possibly-relative path against the repo root.

    Lets the scripts behave the same regardless of the caller's cwd.
    """
    p = Path(path)
    return p if p.is_absolute() else REPO_ROOT / p
