import json
import time
from web3 import Web3
from web3.middleware import geth_poa_middleware
import logging
from dotenv import load_dotenv
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

class AnchorService:
    def __init__(self):
        self.w3 = None
        self.contract = None
        self.account = None
        self.setup_blockchain()
    
    def setup_blockchain(self):
        """Setup Web3 connection and contract."""
        rpc_url = os.getenv('BLOCKCHAIN_RPC', 'http://localhost:8545')
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        
        # For POA chains like Ganache
        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        
        contract_address = os.getenv('CONTRACT_ADDRESS')
        private_key = os.getenv('RELAYER_PRIVATE_KEY')
        
        if not contract_address or not private_key:
            logger.warning("Blockchain configuration missing. Anchoring disabled.")
            return
        
        # Load contract ABI
        with open(os.path.join(os.getcwd(), 'contracts/AnchorRegistry.abi.json'), 'r') as f:
            contract_abi = json.load(f)
        
        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=contract_abi
        )
        
        self.account = self.w3.eth.account.from_key(private_key)
        logger.info(f"Connected to blockchain: {self.w3.is_connected()}")
        logger.info(f"Account: {self.account.address}")
    
    # قبل أي شيء: عند الإعداد
    ANCHORING_ENABLED = os.getenv("ANCHORING_ENABLED", "true").lower() in ("1","true","yes")

    def anchor_data(self, data: dict):
        if not self.ANCHORING_ENABLED if hasattr(self, 'ANCHORING_ENABLED') else not AnchorService.ANCHORING_ENABLED:
            logger.info("Anchoring disabled by ANCHORING_ENABLED=false")
            return None
        if not self.contract:
            logger.warning("Blockchain contract not configured; skipping anchoring.")
            return None
        try:
            data_bytes = json.dumps(data, sort_keys=True).encode()
            data_hash = self.w3.keccak(data_bytes)
            nonce = self.w3.eth.get_transaction_count(self.account.address)
            tx = self.contract.functions.anchorHash(data_hash).build_transaction({
                'from': self.account.address,
                'chainId': int(os.getenv('CHAIN_ID', 1337)),
                'gas': 200000,
                'gasPrice': self.w3.to_wei('1', 'gwei'),
                'nonce': nonce,
            })
            signed = self.w3.eth.account.sign_transaction(tx, private_key=os.getenv('RELAYER_PRIVATE_KEY'))
            tx_hash = self.w3.eth.send_raw_transaction(signed.rawTransaction)
            return tx_hash.hex()
        except Exception as e:
            logger.error("Anchoring failed: %s", e)
            return None


# Example usage
if __name__ == "__main__":
    service = AnchorService()
    data = {"event": "test", "timestamp": time.time()}
    tx_hash = service.anchor_data(data)
    print(f"Transaction hash: {tx_hash}")