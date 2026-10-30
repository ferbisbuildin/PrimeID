// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title PrimeID revocation registry
/// @notice Issuers revoke credentials by signing with their PrimeID issuer key (secp256k1).
///         The signer is recovered on chain, so any wallet may relay the transaction but only
///         the issuer can revoke its own credentials. Revocation is permanent.
///         Credential contents never touch the chain: only a random 16-byte id.
contract PrimeIdRevocationRegistry {
    /// @dev secp256k1n / 2. Signatures with a higher s are malleable and rejected.
    uint256 private constant HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    mapping(address issuer => mapping(bytes32 credentialId => bool)) private revoked;

    event Revoked(address indexed issuer, bytes32 indexed credentialId);

    /// @notice The hash an issuer signs to revoke `credentialId` on this registry and chain.
    function digest(bytes32 credentialId) public view returns (bytes32) {
        bytes32 inner = keccak256(abi.encodePacked(address(this), block.chainid, credentialId));
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
    }

    function revoke(bytes32 credentialId, uint8 v, bytes32 r, bytes32 s) external {
        require(uint256(s) <= HALF_N, "PrimeID: high-s signature");
        address issuer = ecrecover(digest(credentialId), v, r, s);
        require(issuer != address(0), "PrimeID: bad signature");
        if (!revoked[issuer][credentialId]) {
            revoked[issuer][credentialId] = true;
            emit Revoked(issuer, credentialId);
        }
    }

    function isRevoked(address issuer, bytes32 credentialId) external view returns (bool) {
        return revoked[issuer][credentialId];
    }
}
