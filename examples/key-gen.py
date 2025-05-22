from frost_lib import secp256k1_tr as frost
import json


min_signers = 2
max_signers = 3

result = frost.keys_generate_with_dealer(
    max_signers, 
    min_signers
)

print("result: ", json.dumps(result, indent=4))
