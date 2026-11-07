#!/usr/bin/env bash
# Run the NANDA Chapter Protocol server conformance suite against a running kit.
#
#   UMBRELLA=/path/to/Nanda_Chapter_Protocol CHAPTER_URL=http://localhost:8080 scripts/conformance.sh
#
# The suite lives in the (private) umbrella repo under conformance/server/. The
# kit is conformant iff this passes with the same deselection CI uses.
set -euo pipefail
: "${UMBRELLA:?set UMBRELLA to a checkout of Nanda_Chapter_Protocol}"
: "${CHAPTER_URL:=http://localhost:8080}"
cd "$UMBRELLA"
python -m pytest conformance/server/ \
  --chapter-url="$CHAPTER_URL" --http-timeout=30 \
  -m "not requires_persistence" -q "$@"
