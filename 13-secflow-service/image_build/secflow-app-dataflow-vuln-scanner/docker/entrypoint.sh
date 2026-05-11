#!/usr/bin/env bash
set -euo pipefail

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
