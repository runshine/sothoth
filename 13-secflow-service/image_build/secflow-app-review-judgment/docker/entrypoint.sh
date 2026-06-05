#!/usr/bin/env bash
set -euo pipefail

command="${1:-}"

case "$command" in
  ""|"--help"|"-h")
    echo "Usage: secflow-entrypoint <command> [args]"
    echo ""
    echo "Commands:"
    echo "  serve                      Run the REST API service"
    echo "  review-judge [args...]     Run review judgment CLI"
    echo "  bash|sh|python|pi          Run the given command directly"
    echo ""
    exit 0
    ;;
  "serve"|"service")
    shift
    exec python -m app.main serve "$@"
    ;;
  "review-judge")
    shift
    exec python /app/run_review_judge.py "$@"
    ;;
  "bash"|"sh"|"python"|"python3"|"pi")
    exec "$@"
    ;;
  *)
    exec python -m app.main serve "$@"
    ;;
esac