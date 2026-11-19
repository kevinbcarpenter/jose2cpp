#!/usr/bin/env python3
"""Run jose_bench and the go-jose runner and print the results side by side.

    python3 benchmarks/compare.py --jose-bench build/bench-macos/benchmarks/jose_bench
    python3 benchmarks/compare.py --cpp-json cpp.jsonl --go-json go.jsonl   # saved runs

The two runners take turns (C++ then Go, --rounds times) and each case keeps
its best median over the rounds, so a burst of background load on one round
doesn't decide a row. See PLAN.md §Benchmarks for what is measured.
"""

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent


def run(cmd, cwd=None):
    out = subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True,
                         env={**os.environ, "GOFLAGS": "-mod=readonly"})
    return out.stdout


def parse(text):
    meta, results = {}, {}
    for line in text.splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if "meta" in rec:
            meta = rec["meta"]
        else:
            results[rec["case"]] = rec
    return meta, results


def merge(best, results):
    for name, rec in results.items():
        if name not in best or rec["ns_per_op"] < best[name]["ns_per_op"]:
            best[name] = rec


def fmt(ns):
    if ns >= 1e6:
        return f"{ns / 1e6:.2f} ms"
    if ns >= 1e3:
        return f"{ns / 1e3:.1f} µs"
    return f"{ns:.0f} ns"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--jose-bench", help="path to the jose_bench binary (a Release build)")
    ap.add_argument("--cpp-json", help="read jose2cpp results from this file instead of running")
    ap.add_argument("--go-json", help="read go-jose results from this file instead of running")
    ap.add_argument("--rounds", type=int, default=2, help="runs of each side, alternating (default 2)")
    ap.add_argument("--time-ms", type=int, default=200, help="length of one timed sample (default 200)")
    ap.add_argument("--samples", type=int, default=5, help="timed samples per case (default 5)")
    ap.add_argument("--filter", default="", help="only cases whose name contains this")
    ap.add_argument("--save", help="write both sides' raw results (JSON lines) to this file")
    args = ap.parse_args()
    if not args.cpp_json and not args.jose_bench:
        ap.error("give --jose-bench (or --cpp-json)")

    flags = ["--time-ms", str(args.time_ms), "--samples", str(args.samples)]
    if args.filter:
        flags += ["--filter", args.filter]

    cpp_meta, go_meta, cpp, go = {}, {}, {}, {}
    raw = []
    with tempfile.TemporaryDirectory() as tmp:
        go_bin = None
        if not args.go_json:
            # Build first so compile time isn't part of the run.
            go_bin = str(pathlib.Path(tmp) / "go_bench")
            run(["go", "build", "-o", go_bin, "."], cwd=HERE / "go")
        rounds = 1 if (args.cpp_json and args.go_json) else max(1, args.rounds)
        for r in range(rounds):
            if args.cpp_json:
                text = pathlib.Path(args.cpp_json).read_text() if r == 0 else ""
            else:
                print(f"round {r + 1}/{rounds}: jose2cpp", file=sys.stderr)
                text = run([args.jose_bench, "--keys", str(HERE / "keys.json")] + flags)
            if text:
                m, res = parse(text)
                cpp_meta = m or cpp_meta
                merge(cpp, res)
                raw.append(text)
            if args.go_json:
                text = pathlib.Path(args.go_json).read_text() if r == 0 else ""
            else:
                print(f"round {r + 1}/{rounds}: go-jose", file=sys.stderr)
                text = run([go_bin, "--keys", str(HERE / "keys.json")] + flags, cwd=HERE / "go")
            if text:
                m, res = parse(text)
                go_meta = m or go_meta
                merge(go, res)
                raw.append(text)

    if args.save:
        pathlib.Path(args.save).write_text("".join(raw))
    if cpp_meta.get("optimized") is False:
        print("warning: jose_bench was built without optimization", file=sys.stderr)

    print(f"jose2cpp: {cpp_meta.get('openssl', '?')}, {cpp_meta.get('compiler', '?')}")
    print(f"go-jose {go_meta.get('go-jose', '?')}: {go_meta.get('go', '?')}, GOMAXPROCS={go_meta.get('gomaxprocs', '?')}")
    print()
    print("| case | jose2cpp | go-jose | go-jose ÷ jose2cpp |")
    print("|------|---------:|--------:|-------------------:|")
    names = list(cpp) + [n for n in go if n not in cpp]
    for name in names:
        c, g = cpp.get(name), go.get(name)
        ratio = f"{g['ns_per_op'] / c['ns_per_op']:.2f}" if c and g and c["ns_per_op"] > 0 else "-"
        print(f"| {name} | {fmt(c['ns_per_op']) if c else '-'} | {fmt(g['ns_per_op']) if g else '-'} | {ratio} |")
    print()
    print("Median time per operation, best of the rounds. Above 1 in the last column means jose2cpp is faster.")
    missing = sorted(set(cpp) ^ set(go))
    if missing:
        print(f"warning: cases on one side only: {', '.join(missing)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
