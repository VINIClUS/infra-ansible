#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# ACT_BIN permite ao teste unitario substituir o executavel sem iniciar Docker.
exec "${ACT_BIN:-act}" pull_request --dryrun --strict --validate \
  --secret-file /dev/null --env-file /dev/null --input-file /dev/null \
  --var-file /dev/null --workflows .github/workflows/pipeline.yml
