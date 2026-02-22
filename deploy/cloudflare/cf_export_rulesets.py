#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List
import requests


API = "https://api.cloudflare.com/client/v4"


def _hdrs(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "sanal-mulakatim-export/1.0",
    }


def _get(url: str, token: str) -> Any:
    r = requests.get(url, headers=_hdrs(token), timeout=30)
    if not r.ok:
        raise SystemExit(f"GET {url} failed: {r.status_code} {r.text[:200]}")
    j = r.json()
    if not j.get("success"):
        raise SystemExit(f"GET {url} failed: {j}")
    return j["result"]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="export", help="Output directory")
    args = p.parse_args()

    token = os.environ.get("CF_API_TOKEN", "").strip()
    zone = os.environ.get("CF_ZONE_ID", "").strip()
    if not token or not zone:
        print("Missing env: CF_API_TOKEN and/or CF_ZONE_ID", file=sys.stderr)
        return 2

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # List rulesets in the zone
    index_url = f"{API}/zones/{zone}/rulesets"
    rulesets: List[Dict[str, Any]] = _get(index_url, token)

    (out / "rulesets_index.json").write_text(json.dumps(rulesets, ensure_ascii=False, indent=2), encoding="utf-8")

    # Export each ruleset detail
    for rs in rulesets:
        rid = rs.get("id")
        if not rid:
            continue
        detail = _get(f"{API}/zones/{zone}/rulesets/{rid}", token)
        (out / f"ruleset_{rid}.json").write_text(json.dumps(detail, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Exported ruleset {rid}: {rs.get('name')}")

    print(f"Done. Exported {len(rulesets)} rulesets to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
