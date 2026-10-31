#!/usr/bin/env python3
"""Compile a PrimeID test flow into one foundation-passport-drive `run` file.

Each passport-drive process holds one of the hosted kernel's 32 process slots, so a whole
flow must run as a single `run` invocation. Steps (argv):
  feed:<payload.json>   Home -> Enter payload -> type it in chunks -> Verify
  tap:<x>,<y>           tap
  wait:<ms>             pause
  shot:<path.png>       screenshot
Usage: sim-script.py <out.json> step...
"""
import json
import sys

CHUNK = 32  # the sim debug channel stalls on long input_text strings


def feed(path):
    data = open(path).read().strip()
    steps = [{"tap": [345, 750]}, {"wait": 700}, {"tap": [240, 247]}, {"wait": 400}]
    for i in range(0, len(data), CHUNK):
        steps += [{"input_text": data[i:i + CHUNK]}, {"wait": 350}]
    return steps + [{"wait": 300}, {"tap": [240, 350]}, {"wait": 1300}]


out, *args = sys.argv[1:]
actions = []
for a in args:
    kind, _, val = a.partition(":")
    if kind == "feed":
        actions += feed(val)
    elif kind == "tap":
        actions += [{"tap": [int(v) for v in val.split(",")]}, {"wait": 900}]
    elif kind == "wait":
        actions.append({"wait": int(val)})
    elif kind == "shot":
        actions.append({"screenshot": val})
    else:
        sys.exit(f"unknown step {a}")
json.dump(actions, open(out, "w"))
print(f"{len(actions)} actions -> {out}")
