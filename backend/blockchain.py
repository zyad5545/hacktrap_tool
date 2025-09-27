# backend/blockchain.py
import json
import hashlib
import logging
import os
from datetime import datetime

import requests

logger = logging.getLogger(__name__)
RPC = os.getenv("BLOCKCHAIN_RPC", "http://hacktrap_blockchain:8545")
ANCHORS_LOG = os.path.join("data", "anchors.log")


def _json_rpc(payload):
    r = requests.post(RPC, json=payload, timeout=6)
    r.raise_for_status()
    return r.json()


def anchor_via_rpc(payload_obj):
    try:
        payload = json.dumps(payload_obj, sort_keys=True, ensure_ascii=False)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        data_hex = "0x" + digest

        # get accounts
        res = _json_rpc({"jsonrpc": "2.0", "method": "eth_accounts", "params": [], "id": 1})
        accounts = res.get("result", [])
        if not accounts:
            logger.warning("anchor_via_rpc: no accounts returned from RPC")
            return None

        tx = {"from": accounts[0], "to": accounts[0], "value": "0x0", "data": data_hex}
        res2 = _json_rpc({"jsonrpc": "2.0", "method": "eth_sendTransaction", "params": [tx], "id": 2})
        tx_hash = res2.get("result")
        logger.info("anchor_via_rpc: sent tx %s", tx_hash)
        return tx_hash
    except Exception as e:
        logger.exception("anchor_via_rpc failed: %s", e)
        return None


def anchor_data(obj: dict):
    """
    Try to anchor on-chain (via JSON-RPC). If RPC fails, fallback to local SHA256
    with timestamp and a local log file (tamper-evident).
    Returns: tx_hash_or_local_digest (string) or None on failure.
    """
    # 1) try RPC anchor if RPC configured
    try:
        if os.getenv("ANCHORING_ENABLED", "true").lower() in ("1", "true", "yes"):
            tx_hash = anchor_via_rpc(obj)
            if tx_hash:
                return tx_hash
    except Exception:
        logger.exception("anchor_data: rpc attempt failed")

    # 2) fallback: local SHA256 + timestamp, write to data/anchors.log
    try:
        payload = json.dumps(obj, sort_keys=True, ensure_ascii=False)
        stamp = datetime.utcnow().isoformat() + "Z"
        combined = (payload + stamp).encode("utf-8")
        tx_hash = hashlib.sha256(combined).hexdigest()

        os.makedirs(os.path.dirname(ANCHORS_LOG) or ".", exist_ok=True)
        with open(ANCHORS_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({"timestamp": stamp, "tx_hash": tx_hash, "payload": obj}, ensure_ascii=False) + "\n")

        logger.info("anchor_data: local fallback tx_hash=%s", tx_hash)
        return tx_hash
    except Exception:
        logger.exception("anchor_data: local fallback failed")
        return None
