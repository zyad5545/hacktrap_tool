#!/usr/bin/env python3
# tools/clean_xss_csv.py
import sys
from pathlib import Path

p = Path("ai_agent/data/xss_payloads.csv")
out = Path("ai_agent/data/xss_payloads.csv.clean")

if not p.exists():
    print("Missing:", p)
    sys.exit(1)

with p.open("r", encoding="utf-8", errors="replace") as f_in, out.open("w", encoding="utf-8") as f_out:
    for i, raw in enumerate(f_in, start=1):
        line = raw.rstrip("\n")
        # if odd number of double quotes -> try to fix by removing stray quotes
        if line.count('"') % 2 == 1:
            # common patterns: many doubled quotes or surrounding quotes — remove all double-quotes
            # (this is conservative; you may want to inspect the original afterwards)
            fixed = line.replace('"', '')
            f_out.write(fixed + "\n")
            print(f"fixed line {i}: removed unbalanced quotes")
        else:
            f_out.write(line + "\n")

print("Cleaned file written to:", out)
print("If output looks good, replace original:")
print("  mv ai_agent/data/xss_payloads.csv{.clean,}")
