#!/usr/bin/env python3
"""Generate OpenSSL unit tests with an LLM.

See README.md for usage.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from llmtest.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
