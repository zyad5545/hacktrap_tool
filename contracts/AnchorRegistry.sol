pragma solidity ^0.8.0;

/**
 * @title AnchorRegistry
 * @dev A smart contract for anchoring hashes of security events to the blockchain.
 */
contract AnchorRegistry {
    // Mapping to store anchored hashes
    mapping(bytes32 => bool) public anchoredHashes;
    
    // Event emitted when a hash is anchored
    event HashAnchored(bytes32 indexed hash, address indexed sender, uint256 timestamp);
    
    /**
     * @dev Anchor a hash to the blockchain.
     * @param hash The hash to anchor.
     */
    function anchorHash(bytes32 hash) public {
        require(!anchoredHashes[hash], "Hash already anchored");
        
        anchoredHashes[hash] = true;
        emit HashAnchored(hash, msg.sender, block.timestamp);
    }
    
    /**
     * @dev Check if a hash is already anchored.
     * @param hash The hash to check.
     * @return bool True if the hash is anchored.
     */
    function isHashAnchored(bytes32 hash) public view returns (bool) {
        return anchoredHashes[hash];
    }
}
