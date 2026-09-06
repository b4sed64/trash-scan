#!/bin/sh
# Regenerate the Nuclei template allowlist manifest after a reviewed change.
# Run from the backend/ directory. Commit the result with the template change.
set -e
cd "$(dirname "$0")/../templates"
out=nuclei-manifest.json
cd nuclei
{
  echo '{'
  echo '  "_comment": "Immutable reviewed Nuclei template allowlist. sha256 of each file; the adapter refuses to run if a file does not match (PRD 12.5/12.6). Regenerate deliberately via scripts/gen_template_manifest.sh after review.",'
  echo '  "templates": {'
  first=1
  for f in *.yaml; do
    h=$(sha256sum "$f" | cut -d' ' -f1)
    [ $first -eq 0 ] && echo ','
    printf '    "%s": "%s"' "$f" "$h"
    first=0
  done
  echo
  echo '  }'
  echo '}'
} > "../$out"
echo "wrote templates/$out"
