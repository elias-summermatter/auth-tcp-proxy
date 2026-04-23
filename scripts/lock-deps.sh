#!/usr/bin/env bash
#
# Regenerate requirements.txt from requirements.in with SHA-256 hashes
# for every package (direct + transitive). Commit the result — the
# Dockerfile installs with --require-hashes, so PyPI can't silently
# swap a malicious build into your image between commits.
#
# Run after changing requirements.in, or periodically to pick up
# security-patched versions.
#
# Runs inside a disposable Docker container so you don't need pip-tools
# installed locally and so the lockfile matches what the image will use.
set -euo pipefail

cd "$(dirname "$0")/.."

docker run --rm \
  -v "$PWD:/work" -w /work \
  --user "$(id -u):$(id -g)" \
  python:3.12-slim \
  sh -c '
    set -eu
    pip install --quiet --disable-pip-version-check --root-user-action=ignore pip-tools
    pip-compile --generate-hashes --resolver=backtracking \
      --output-file requirements.txt requirements.in
  '

echo
echo "Regenerated requirements.txt with hashes. Review the diff, then commit."
