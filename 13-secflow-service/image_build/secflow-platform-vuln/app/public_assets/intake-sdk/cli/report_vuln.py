#!/usr/bin/env python3
import json
import sys
from urllib import request


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: report_vuln.py <base_url> <payload.json>")
        return 1

    base_url = sys.argv[1].rstrip("/")
    payload_path = sys.argv[2]
    with open(payload_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    req = request.Request(
        f"{base_url}/api/vuln/public/intake/submissions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=15) as response:
        print(response.read().decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
