from eth_utils.crypto import keccak

from frost_lib import secp256k1_evm as frost

min_signers = 2
max_signers = 3

result = frost.keys_generate_with_dealer(max_signers, min_signers)
shares = result.shares
pubkey_package = result.pubkey_package
print("publicKey: ", pubkey_package.verifying_key)
# print("Result:", result)

key_packages = {}
for identifier, secret_share in result.shares.items():
    key_packages[identifier] = frost.key_package_from(secret_share)

nonces_map = {}
commitments_map = {}
"""
==========================================================================
Round 1: generating nonces and signing commitments for each participant
==========================================================================
"""
for identifier, _ in list(result.shares.items())[:min_signers]:
    result = frost.round1_commit(
        key_packages[identifier].signing_share,
    )
    nonces_map[identifier] = result.nonces
    commitments_map[identifier] = result.commitments

signature_shares = {}
message = b"message to sign"

print("message: ", message)
print("message hash: ", "0x" + keccak(message).hex())
signing_package = frost.signing_package_new(commitments_map, message)
"""
==========================================================================
Round 2: each participant generates their signature share
==========================================================================
"""
for identifier, _ in nonces_map.items():
    signature_share = frost.round2_sign(signing_package, nonces_map[identifier], key_packages[identifier])
    signature_shares[identifier] = signature_share
"""
==========================================================================
Aggregation: collects the signing shares from all participants,
generates the final signature.
==========================================================================
"""
group_signature = frost.aggregate(signing_package, signature_shares, pubkey_package)
print("signature: ", group_signature)

verified1 = frost.verify_group_signature(group_signature, message, pubkey_package)
print("verified: ", verified1)

# print("nonce address: ", frost.get_nonce_address(signing_package, pubkey_package));
# print("nonce address: ", dir(frost._curve));
