# backend/blockchain.py
import json
import hashlib
from datetime import datetime

def anchor_data(data: dict):
    """
    Lightweight anchoring: returns SHA256 hash of canonical JSON + timestamp.
    This avoids requiring web3 when you just need a tamper-evident anchor.
    Replace with web3 logic when you want real-chain anchoring.
    """
    payload = json.dumps(data, sort_keys=True, ensure_ascii=False)
    stamp = datetime.utcnow().isoformat() + "Z"
    combined = (payload + stamp).encode("utf-8")
    tx_hash = hashlib.sha256(combined).hexdigest()
    # optional: persist to local log file if you want an audit trail
    try:
        with open("data/anchors.log", "a", encoding="utf-8") as f:
            f.write(json.dumps({"timestamp": stamp, "tx_hash": tx_hash, "payload": data}, ensure_ascii=False) + "\n")
    except Exception:
        pass
    return tx_hash
