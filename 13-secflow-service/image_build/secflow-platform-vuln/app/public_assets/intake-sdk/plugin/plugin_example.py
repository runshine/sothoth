import json
import requests


def report(base_url: str, token: str, payload: dict) -> dict:
    response = requests.post(
        f"{base_url.rstrip('/')}/api/vuln/public/intake/submissions",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        data=json.dumps(payload),
        timeout=15,
    )
    response.raise_for_status()
    return response.json()
