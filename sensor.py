"""
Feeds flows to the console at /api/flows.

Three modes:

  python sensor.py demo                        synthetic traffic, no capture needed
  python sensor.py replay flows.csv --rate 40  push an existing CICFlowMeter CSV
  python sensor.py follow live.csv             tail a CSV a sensor is still writing

`follow` is the real deployment path: point CICFlowMeter (or any tool that emits
per-flow features) at an interface, have it append to a CSV, and run this against
that file.
"""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import os
import random
import sys
import time
from pathlib import Path

import urllib.error
import urllib.request

HERE = Path(__file__).parent
PROFILES = json.loads((HERE / "demo_profiles.json").read_text())

INTERNAL = [f"10.42.{n // 254}.{n % 254 + 1}" for n in range(60)]
EXTERNAL = ["203.0.113.{}".format(i) for i in range(2, 40)] + \
           ["198.51.100.{}".format(i) for i in range(2, 30)]
SERVICES = [(443, "https"), (80, "http"), (22, "ssh"), (53, "dns"),
            (3306, "mysql"), (8080, "http-alt"), (445, "smb")]


def post(url: str, flows: list[dict], timeout: float = 10.0) -> dict:
    body = json.dumps({"flows": flows}).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def jitter(value: float, spread: float, rng: random.Random) -> float:
    return value * rng.uniform(1 - spread, 1 + spread)


def make_demo_flow(rng: random.Random, attack: bool) -> dict:
    """
    Build a synthetic flow from a stored profile plus noise.

    The attack profiles were derived from the model's own decision regions, so they
    are a way to exercise the console end to end -- they are not captured traffic and
    say nothing about how the model performs on real intrusions.
    """
    if attack:
        name = rng.choice(["heavy-response-flood", "sustained-large-transfer"])
        spread = 0.015
    else:
        name = rng.choices(["web-session", "idle-baseline"], weights=[3, 2])[0]
        spread = 0.25

    flow = {k: jitter(v, spread, rng) if abs(v) > 1e-9 else v
            for k, v in PROFILES["profiles"][name]["features"].items()}

    port, service = rng.choice(SERVICES)
    if attack:
        src, dst = rng.choice(EXTERNAL), rng.choice(INTERNAL)
    else:
        src, dst = rng.choice(INTERNAL), rng.choice(EXTERNAL)

    flow.update({
        "flow_id": f"{time.time_ns():x}{rng.randrange(16 ** 3):03x}",
        "src_ip": src,
        "src_port": rng.randrange(1024, 65535),
        "dst_ip": dst,
        "dst_port": port,
        "protocol_name": service,
        "source": f"demo/{name}",
    })
    return flow


def demo(args) -> None:
    rng = random.Random(args.seed)
    interval = 1.0 / max(args.rate, 0.001)
    sent = 0
    print(f"demo traffic -> {args.url} at ~{args.rate}/s "
          f"({args.attack_ratio:.0%} attack-shaped). ctrl-c to stop.")
    try:
        while args.count == 0 or sent < args.count:
            burst = max(1, int(args.rate * 0.25))
            flows = [make_demo_flow(rng, rng.random() < args.attack_ratio)
                     for _ in range(burst)]
            send(args.url, flows)
            sent += burst
            time.sleep(interval * burst)
    except KeyboardInterrupt:
        print(f"\nstopped after {sent} flows")


def rows_from_csv(path: Path):
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as fh:
        for row in csv.DictReader(fh):
            yield {k.strip(): v for k, v in row.items() if k}


def replay(args) -> None:
    path = Path(args.path)
    if not path.exists():
        sys.exit(f"no such file: {path}")
    interval = 1.0 / max(args.rate, 0.001)
    print(f"replaying {path.name} -> {args.url} at ~{args.rate}/s")
    sent = 0
    try:
        for _ in itertools.count() if args.loop else [0]:
            buffer: list[dict] = []
            for row in rows_from_csv(path):
                row.setdefault("source", path.name)
                buffer.append(row)
                if len(buffer) >= max(1, int(args.rate * 0.25)):
                    send(args.url, buffer)
                    sent += len(buffer)
                    time.sleep(interval * len(buffer))
                    buffer = []
            if buffer:
                send(args.url, buffer)
                sent += len(buffer)
    except KeyboardInterrupt:
        print(f"\nstopped after {sent} flows")


def follow(args) -> None:
    """Tail a CSV that a capture tool is appending to."""
    path = Path(args.path)
    while not path.exists():
        print(f"waiting for {path} ...")
        time.sleep(1)

    with path.open(newline="", encoding="utf-8-sig", errors="replace") as fh:
        header = fh.readline()
        if not header:
            sys.exit("file has no header row")
        fields = [h.strip() for h in next(csv.reader([header]))]
        fh.seek(0, os.SEEK_END)
        print(f"following {path.name} ({len(fields)} columns) -> {args.url}")

        buffer: list[dict] = []
        last_flush = time.time()
        try:
            while True:
                line = fh.readline()
                if line:
                    values = next(csv.reader([line]), None)
                    if values and len(values) == len(fields):
                        row = dict(zip(fields, values))
                        row.setdefault("source", path.name)
                        buffer.append(row)
                if buffer and (len(buffer) >= 200 or time.time() - last_flush > 0.5):
                    send(args.url, buffer)
                    buffer, last_flush = [], time.time()
                if not line:
                    time.sleep(0.2)
        except KeyboardInterrupt:
            print("\nstopped")


def send(url: str, flows: list[dict]) -> None:
    try:
        result = post(url, flows)
        if result.get("dropped"):
            print(f"console dropped {result['dropped']} flows "
                  f"(queue at {result.get('queue_depth')})")
    except urllib.error.URLError as exc:
        print(f"cannot reach {url}: {exc.reason}. Is app.py running?")
        time.sleep(2)


def main() -> None:
    # --url lives on a shared parent so it works either side of the subcommand:
    # `sensor.py --url X demo` and `sensor.py demo --url X` both parse.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--url", default="http://127.0.0.1:8000/api/flows",
                        help="console ingest endpoint")

    parser = argparse.ArgumentParser(description=__doc__, parents=[common],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="mode", required=True)

    d = sub.add_parser("demo", help="generate synthetic flows", parents=[common])
    d.add_argument("--rate", type=float, default=12, help="flows per second")
    d.add_argument("--attack-ratio", type=float, default=0.15)
    d.add_argument("--count", type=int, default=0, help="0 = run until stopped")
    d.add_argument("--seed", type=int, default=None)
    d.set_defaults(func=demo)

    r = sub.add_parser("replay", help="replay a CICFlowMeter CSV", parents=[common])
    r.add_argument("path")
    r.add_argument("--rate", type=float, default=40)
    r.add_argument("--loop", action="store_true")
    r.set_defaults(func=replay)

    f = sub.add_parser("follow", help="tail a CSV being written live", parents=[common])
    f.add_argument("path")
    f.set_defaults(func=follow)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
