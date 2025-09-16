from web3 import Web3
import json
import os
from dotenv import load_dotenv

load_dotenv()

def get_web3():
    """Initialize Web3 connection"""
    rpc_url = os.getenv('BLOCKCHAIN_RPC', 'http://localhost:8545')
    return Web3(Web3.HTTPProvider(rpc_url))

def load_contract():
    """Load the contract ABI and address"""
    contract_address = os.getenv('CONTRACT_ADDRESS')
    
    # In a real implementation, you would load this from a file
    contract_abi = [
        {
            "inputs": [{"internalType": "bytes32", "name": "hash", "type": "bytes32"}],
            "name": "anchorHash",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [{"internalType": "bytes32", "name": "hash", "type": "bytes32"}],
            "name": "anchoredHashes",
            "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
            "stateMutability": "view",
            "type": "function"
        }
    ]
    
    w3 = get_web3()
    return w3.eth.contract(address=contract_address, abi=contract_abi)

def anchor_data(data):
    """
    Anchor data to the blockchain by storing its hash
    Returns transaction hash
    """
    try:
        # Convert data to hash
        data_str = json.dumps(data, sort_keys=True)
        data_hash = Web3.keccak(text=data_str)
        
        # Get contract instance
        contract = load_contract()
        
        # Get account and private key
        private_key = os.getenv('RELAYER_PRIVATE_KEY')
        account = Web3().eth.account.from_key(private_key)
        
        # Build transaction
        nonce = Web3().eth.get_transaction_count(account.address)
        tx = contract.functions.anchorHash(data_hash).build_transaction({
            'chainId': int(os.getenv('CHAIN_ID', 1337)),
            'gas': 100000,
            'gasPrice': Web3.to_wei('10', 'gwei'),
            'nonce': nonce,
        })
        
        # Sign and send transaction
        signed_tx = Web3().eth.account.sign_transaction(tx, private_key)
        tx_hash = Web3().eth.send_raw_transaction(signed_tx.rawTransaction)
        
        return tx_hash.hex()
    
    except Exception as e:
        print(f"Error anchoring data to blockchain: {e}")
        return None