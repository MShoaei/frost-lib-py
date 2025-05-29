from frost_lib import secp256k1_tr as frost

min_signers = 2
max_signers = 3

result = frost.keys_generate_with_dealer(max_signers, min_signers)

print("result: ", result.model_dump_json(indent=4))
