#!/usr/bin/env bash
set -euo pipefail

bootstrap_runtime_home() {
  local bootstrap_dir="${PI_BOOTSTRAP_DIR:-/opt/runtime-bootstrap}"

  restore_archive() {
    local archive_path="$1"
    local target_dir_name="$2"

    if [ ! -f "$archive_path" ]; then
      return 0
    fi

    echo "[bootstrap] restoring /root/${target_dir_name} from ${archive_path}"
    rm -rf "/root/${target_dir_name}"
    mkdir -p /root
    tar --no-same-owner -xzf "$archive_path" -C /root
  }

  restore_archive "${bootstrap_dir}/pi-home.tar.gz" ".pi"
  restore_archive "${bootstrap_dir}/copilot-home.tar.gz" ".copilot"
}

bootstrap_runtime_home

command="${1:-}"

case "$command" in
  ""|"--help"|"-h")
    exec python /app/run_vuln_scan.py --help
    ;;
  "vuln-scan")
    shift
    exec python /app/run_vuln_scan.py "$@"
    ;;
  "framework-run")
    shift
    exec python -m app.pi_vuln_core.main "$@"
    ;;
  "serve"|"service")
    shift
    exec python -m app.main serve "$@"
    ;;
  "bash"|"sh"|"python"|"python3"|"pi")
    exec "$@"
    ;;
  *)
    exec python /app/run_vuln_scan.py "$@"
    ;;
esac
