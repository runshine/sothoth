#!/usr/bin/env python3
import json
import sys
from urllib import request


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: report_vuln.py <base_url> <token> <payload.json>")
        return 1

    base_url = sys.argv[1].rstrip("/")
    token = sys.argv[2]
    payload_path = sys.argv[3]
    with open(payload_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    req = request.Request(
        f"{base_url}/api/vuln/public/intake/submissions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with request.urlopen(req, timeout=15) as response:
        print(response.read().decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
