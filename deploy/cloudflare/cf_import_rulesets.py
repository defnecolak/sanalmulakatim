#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict
import requests


API = "https://api.cloudflare.com/client/v4"


def _hdrs(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "sanal-mulakatim-import/1.0",
    }


def _put(url: str, token: str, body: Any) -> Any:
    r = requests.put(url, headers=_hdrs(token), json=body, timeout=60)
    if not r.ok:
        raise SystemExit(f"PUT {url} failed: {r.status_code} {r.text[:200]}")
    j = r.json()
    if not j.get("success"):
        raise SystemExit(f"PUT {url} failed: {j}")
    return j["result"]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--in", dest="indir", default="export", help="Input directory created by export")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    token = os.environ.get("CF_API_TOKEN", "").strip()
    zone = os.environ.get("CF_ZONE_ID", "").strip()
    if not token or not zone:
        print("Missing env: CF_API_TOKEN and/or CF_ZONE_ID", file=sys.stderr)
        return 2

    indir = Path(args.indir)
    if not indir.exists():
        print(f"Input dir not found: {indir}", file=sys.stderr)
        return 3

    for f in sorted(indir.glob("ruleset_*.json")):
        detail = json.loads(f.read_text(encoding="utf-8"))
        rid = detail.get("id")
        if not rid:
            continue

        # Cloudflare expects the body WITHOUT 'id' on PUT in many endpoints.
        body = dict(detail)
        body.pop("id", None)

        url = f"{API}/zones/{zone}/rulesets/{rid}"
        if args.dry_run:
            print(f"[DRY] Would PUT {url} (name={detail.get('name')})")
            continue

        _put(url, token, body)
        print(f"Updated ruleset {rid}: {detail.get('name')}")

    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
