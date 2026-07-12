#!/usr/bin/env bash
set -euo pipefail

runner_name=""
runner_labels=""
runner_work=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)
      runner_name="$2"
      shift 2
      ;;
    --labels)
      runner_labels="$2"
      shift 2
      ;;
    --work)
      runner_work="$2"
      shift 2
      ;;
    --url | --token)
      shift 2
      ;;
    --unattended | --replace)
      shift
      ;;
    *)
      echo "unexpected fake runner argument: $1" >&2
      exit 2
      ;;
  esac
done

test -n "$runner_name"
test -n "$runner_labels"
test -n "$runner_work"

mkdir -p "$runner_work" bin
printf '{"name":"%s","labels":"%s","work":"%s"}\n' \
  "$runner_name" "$runner_labels" "$runner_work" > .runner

cat > bin/Runner.Listener <<'RUNNER_LISTENER'
#!/usr/bin/env bash
set -euo pipefail
test "${1:-}" = "--version"
printf '%s\n' "2.335.1-fake"
RUNNER_LISTENER
chmod 0755 bin/Runner.Listener

cat > svc.sh <<'SERVICE_HELPER'
#!/usr/bin/env bash
set -euo pipefail

action="${1:-}"

if [[ "$action" == "install" ]]; then
  runner_user="${2:?runner service user is required}"
  runner_name="$(sed -n 's/.*"name":"\([^"]*\)".*/\1/p' .runner)"
  safe_name="$(printf '%s' "$runner_name" | tr -c 'A-Za-z0-9_.-' '-')"
  service_name="actions.runner.fake.${safe_name}.service"

  cat > "/etc/systemd/system/${service_name}" <<UNIT
[Unit]
Description=Offline fake GitHub Actions runner
After=network.target

[Service]
ExecStart=${PWD}/run.sh
User=${runner_user}
WorkingDirectory=${PWD}
KillMode=process
KillSignal=SIGTERM
TimeoutStopSec=30
Restart=always

[Install]
WantedBy=multi-user.target
UNIT

  printf '%s\n' "$service_name" > .service
elif [[ "$action" == "start" ]]; then
  systemctl start "$(cat .service)"
else
  echo "unsupported fake service action: $action" >&2
  exit 2
fi
SERVICE_HELPER
chmod 0755 svc.sh
