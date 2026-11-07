#!/usr/bin/env bash
# Scoped permission for the disposable public validation VM, never other hosts.
set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != true ||
      "${RUNNER_ENVIRONMENT:-}" != github-hosted ||
      "${RUNNER_OS:-}" != Linux ||
      "${GITHUB_JOB:-}" != validate ||
      "${GITHUB_REPOSITORY:-}" != VINIClUS/infra-ansible ||
      "${ImageOS:-}" != ubuntu26 || "$EUID" == 0 ]]; then
  printf '%s\n' 'hosted_userns_scope_refused: requires unprivileged public validate on GitHub-hosted ubuntu26' >&2
  exit 1
fi

if [[ -z "${RUNNER_TEMP:-}" || ! -d "$RUNNER_TEMP" ||
      ! -x /usr/bin/unshare || ! -x /usr/sbin/apparmor_parser ||
      ! -r /sys/module/apparmor/parameters/enabled ||
      ! -r /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]]; then
  printf '%s\n' 'hosted_userns_prerequisite_absent: expected Ubuntu AppArmor and namespace tools' >&2
  exit 1
fi
read -r enabled < /sys/module/apparmor/parameters/enabled
read -r restriction < /proc/sys/kernel/apparmor_restrict_unprivileged_userns
if [[ "$enabled" != Y ]]; then
  printf '%s\n' 'hosted_userns_apparmor_unavailable: refusing to alter another security configuration' >&2
  exit 1
fi
printf 'Hosted native isolation: ImageOS=%s ImageVersion=%s AppArmor=%s userns_restriction=%s uid=%s\n' \
  "$ImageOS" "${ImageVersion:-unknown}" "$enabled" "$restriction" "$EUID"

profile=$(mktemp "${RUNNER_TEMP%/}/cnesdata-unshare.XXXXXX")
trap 'rm -f "$profile"' EXIT
# Ubuntu's documented application-specific userns allowance. The kernel's
# user/network namespaces remain mandatory; no host-wide sysctl is changed.
cat > "$profile" <<'APPARMOR'
abi <abi/4.0>,
include <tunables/global>
profile cnesdata-ci-unshare /usr/bin/unshare flags=(unconfined) {
  userns,
}
APPARMOR
# Load only this executable's profile into the disposable VM; no persistent cache.
sudo -n /usr/sbin/apparmor_parser --add --skip-cache "$profile"
printf '%s\n' 'Loaded unshare-specific userns permission; exact unprivileged native preflight remains required'
