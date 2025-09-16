import json
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

class KMSSigner:
    def __init__(self, private_key_path: str = None):
        self.private_key = None
        if private_key_path:
            self.load_private_key(private_key_path)
    
    def load_private_key(self, path: str):
        """Load a private key from a file."""
        with open(path, 'rb') as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    
    def sign_data(self, data: dict) -> str:
        """Sign data and return a signature."""
        if not self.private_key:
            raise ValueError("Private key not loaded")
        
        # Convert data to JSON string and encode
        data_str = json.dumps(data, sort_keys=True)
        data_bytes = data_str.encode()
        
        # Sign the data
        signature = self.private_key.sign(
            data_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        
        # Return base64 encoded signature
        return base64.b64encode(signature).decode()
    
    def verify_signature(self, data: dict, signature: str, public_key_path: str) -> bool:
        """Verify a signature with a public key."""
        with open(public_key_path, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        
        data_str = json.dumps(data, sort_keys=True)
        data_bytes = data_str.encode()
        sig_bytes = base64.b64decode(signature)
        
        try:
            public_key.verify(
                sig_bytes,
                data_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False

# Example usage
if __name__ == "__main__":
    signer = KMSSigner("private_key.pem")
    data = {"event": "test", "timestamp": "2023-10-05"}
    signature = signer.sign_data(data)
    print("Signature:", signature)
    
    # Verify
    is_valid = signer.verify_signature(data, signature, "public_key.pem")
    print("Signature valid:", is_valid)