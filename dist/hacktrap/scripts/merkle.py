import hashlib
from typing import List

def compute_hash(data: str) -> str:
    """Compute SHA-256 hash of data."""
    return hashlib.sha256(data.encode()).hexdigest()

def build_merkle_tree(elements: List[str]) -> List[List[str]]:
    """Build a Merkle tree from a list of elements."""
    if not elements:
        return []
    
    # Ensure even number of elements by duplicating last if needed
    if len(elements) % 2 != 0:
        elements.append(elements[-1])
    
    tree = [elements]
    current_level = elements
    
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1]
            combined = left + right
            next_level.append(compute_hash(combined))
        tree.append(next_level)
        current_level = next_level
    
    return tree

def get_merkle_root(elements: List[str]) -> str:
    """Get the Merkle root from a list of elements."""
    tree = build_merkle_tree(elements)
    if not tree:
        return ""
    return tree[-1][0]

# Example usage
if __name__ == "__main__":
    data = ["event1", "event2", "event3", "event4"]
    tree = build_merkle_tree(data)
    root = get_merkle_root(data)
    print("Merkle Root:", root)