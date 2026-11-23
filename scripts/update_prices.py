"""Refresh prices.json from AWS's public price data (the files behind aws.amazon.com/ec2/pricing).

Run before a release: python scripts/update_prices.py
The app ships the result, so it never has to ask AWS for prices (no account, no cost, works offline).
"""
import gzip
import json
import os
import sys
import urllib.parse
import urllib.error
import urllib.request
from datetime import date

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from proxy_app import REGIONS, SERVER_SIZES  # noqa: E402

BASE = "https://b0.p.awsstatic.com/pricing/2.0/meteredUnitMaps"
NAMES = {  # region code -> AWS's location name in its price files
    "ap-south-1": "Asia Pacific (Mumbai)", "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)", "ap-northeast-1": "Asia Pacific (Tokyo)",
    "eu-west-1": "EU (Ireland)", "eu-west-2": "EU (London)", "eu-central-1": "EU (Frankfurt)",
    "eu-north-1": "EU (Stockholm)", "us-east-1": "US East (N. Virginia)", "us-east-2": "US East (Ohio)",
    "us-west-2": "US West (Oregon)", "ca-central-1": "Canada (Central)", "sa-east-1": "South America (Sao Paulo)",
    "me-central-1": "Middle East (UAE)", "af-south-1": "Africa (Cape Town)",
}


def fetch(path):
    with urllib.request.urlopen(f"{BASE}/{path}", timeout=60) as r:
        raw = r.read()
    return json.loads(gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw)["regions"]


def region_entries(table, name):
    """A region's price entries; the files spell Europe as 'EU' or 'Europe' depending on the file."""
    for n in (name, name.replace("EU (", "Europe (")):
        if n in table:
            return table[n]
    raise KeyError(name)


def find(entries, *words):
    for key, value in entries.items():
        if all(w in key for w in words):
            return float(value["price"])
    raise KeyError(words)


def main():
    ebs, vpc, dt = fetch("ec2/USD/current/ebs.json"), fetch("vpc/USD/current/vpc.json"), \
        fetch("datatransfer/USD/current/datatransfer.json")
    out = {"updated": date.today().isoformat(), "source": "aws.amazon.com public price list", "regions": {}}
    for code in REGIONS:
        name = NAMES[code]
        for n in (name, name.replace("EU (", "Europe (")):  # the EC2 files may spell Europe out
            try:
                ec2 = fetch(f"ec2/USD/current/ec2-ondemand-without-sec-sel/{urllib.parse.quote(n)}/Linux/index.json")
                break
            except urllib.error.HTTPError:
                continue
        else:
            raise KeyError(f"no EC2 prices for {name}")
        servers = region_entries(ec2, name)
        sizes = {}
        for size in SERVER_SIZES:
            family, kind = size.split(".")
            sizes[size] = next(float(v["price"]) for k, v in servers.items()
                               if v.get("Instance Type") == size or k.startswith(f"{family} {kind} "))
        out["regions"][code] = {
            "server": sizes,
            "ipv4_hour": find(region_entries(vpc, name), "In use Public IPv4"),
            "gp3_gb_month": find(region_entries(ebs, name), "gp3 GB Mo"),
            "data_out_gb": find(region_entries(dt, name), "External Outbound Next 10 TB"),
        }
        print(code, out["regions"][code])
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "prices.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
        f.write("\n")


if __name__ == "__main__":
    main()
