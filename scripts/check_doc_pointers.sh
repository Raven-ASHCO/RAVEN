#!/usr/bin/env bash
# docs/ is the single source of truth. A node/*.md whose basename also exists
# in docs/ must be a short pointer stub to that docs/ file — never a second,
# silently diverging copy (the stale node/ copies once contradicted docs/ on
# security status). Exit 1 on any violation.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
bad=0
for f in node/*.md; do
  base="${f##*/}"
  [[ -f "docs/$base" ]] || continue
  lines=$(wc -l <"$f" | tr -d ' ')
  if [[ "$lines" -gt 12 ]] || ! grep -qF "(../docs/$base)" "$f"; then
    echo "DUPLICATE_DOC: $f duplicates docs/$base — replace it with a pointer stub to ../docs/$base" >&2
    bad=1
  fi
done
if [[ "$bad" -ne 0 ]]; then
  exit 1
fi
echo "doc pointers OK (node/*.md duplicates are stubs to docs/)"
