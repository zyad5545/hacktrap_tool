# ai_engine/prepare_xss_csv.py
import pandas as pd
from pathlib import Path

wordlists = {
    "common.txt": "normal",
    "xss_payloads.txt": "xss",
    "sqli_payloads.txt": "sqli",
    "bruteforce_payloads.txt": "bruteforce"
}

output_dir = Path("./ai_agent/data")
output_dir.mkdir(parents=True, exist_ok=True)

for file_name, label in wordlists.items():
    file_path = Path("../data/wordlists") / file_name
    if not file_path.exists():
        print(f"{file_name} not found, skipping.")
        continue

    with open(file_path, encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    df = pd.DataFrame({
        "text": lines,
        "label": [label]*len(lines)
    })

    csv_name = file_name.replace(".txt", ".csv")
    df.to_csv(output_dir / csv_name, index=False, encoding="utf-8")
    print(f"Saved {csv_name} with {len(lines)} rows.")

print("✅ All CSV files for AI training created successfully!")
