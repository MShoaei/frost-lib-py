from frost_lib import secp256k1 as frost


def corrupt_hex(input):
    lst = list(input)
    lst[0] = "1" if lst[0] == "0" else "0"
    return "".join(lst)


min_signers = 2
max_signers = 3

result = frost.keys_generate_with_dealer(max_signers, min_signers)
shares = result.shares
pubkey_package = result.pubkey_package
print("publicKey: ", pubkey_package.verifying_key)
# print("Result:", result)

malicues_id = list(result.shares.keys())[0]
print("malicues ID: ", malicues_id)

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
signing_party = list(result.shares.keys())[:min_signers]
for identifier in signing_party:
    result = frost.round1_commit(
        key_packages[identifier].signing_share,
    )
    nonces_map[identifier] = result.nonces
    commitments_map[identifier] = result.commitments

signature_shares = {}
message = b"message to sign"
print("message: ", message)
signing_package = frost.signing_package_new(commitments_map, message)
"""
==========================================================================
Round 2: each participant generates their signature share
==========================================================================
"""
for identifier in signing_party:
    signature_share = frost.round2_sign(signing_package, nonces_map[identifier], key_packages[identifier])
    if identifier == malicues_id:
        signature_share.share = corrupt_hex(signature_share.share)
    signature_shares[identifier] = signature_share
"""
==========================================================================
Aggregation: collects the signing shares from all participants,
generates the final signature.
==========================================================================
"""
group_signature = ""
try:
    group_signature = frost.aggregate(signing_package, signature_shares, pubkey_package)
except Exception as e:
    if "signature share" in f"{e}":
        print("trying to detect cheater ...")
        for identifier in signing_party:
            share_verified = frost.verify_share(
                identifier,
                pubkey_package.verifying_shares[identifier],
                signature_shares[identifier],
                signing_package,
                pubkey_package.verifying_key,
            )
            if not share_verified:
                print("detected malicues: ", identifier)
                exit()
    raise e

print("signature: ", group_signature)

verified1 = frost.verify_group_signature(group_signature, message, pubkey_package)
verified2 = frost.verify_group_signature(group_signature, b"wrong message", pubkey_package)

print("correct message verified: ", verified1)
print("  wrong message verified: ", verified2)
