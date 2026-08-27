#!/usr/bin/env python3
"""Register a new standalone test binary in test/build.info.

Thin CLI wrapper around llmtest.buildinfo; see that module for the details of
why a build.info entry is required at all.

    ./register_test.py <test-name> [source.c]

`source.c` is relative to test/ and defaults to <test-name>.c. Experiment-generated
tests pass e.g. generated/<name>/<name>.c.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from llmtest import buildinfo  # noqa: E402


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print("usage: {} <test-name> [source.c]".format(sys.argv[0]), file=sys.stderr)
        return 1

    name = sys.argv[1]
    source = sys.argv[2] if len(sys.argv) == 3 else None

    try:
        list_added, block_added = buildinfo.register(name, source)
    except buildinfo.BuildInfoError as exc:
        print("register_test: {}".format(exc), file=sys.stderr)
        return 1

    if not list_added and not block_added:
        print("'{}' is already registered in {}; nothing to do.".format(
            name, buildinfo.BUILD_INFO))
        return 0

    if list_added:
        print("added '{}' to the test program list".format(name))
    if block_added:
        print("added SOURCE/INCLUDE/DEPEND block for '{}' (source: {})".format(
            name, source or name + ".c"))
    print("updated {}".format(buildinfo.BUILD_INFO))
    print("run a compile/compile-cov (which re-runs ./config) to pick this up")
    return 0


if __name__ == "__main__":
    sys.exit(main())
