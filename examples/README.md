## Installation

```bash
$ python -m venv venv
$ source venv/bin/activate

$ maturin develop
$ pip install -r requirements.txt
```

## Run
Run all examples from root directory

**Create master key**
```bash
$ python examples/dkg.py <key-file-name> <threshold> <num-signers>

# example
$ python examples/dkg.py wallet-1 2 3
```

**Spend BTC utxos in master key address**
```bash
$ python examples/btc-tx-normal.py <key-file-name>

# example
$ python examples/btc-tx-normal.py wallet-1
```

**Spend BTC utxos in tweaked address**
```bash
$ python examples/btc-tx-tweak.py <key-file-name>

# example
$ python examples/btc-tx-tweak.py wallet-1
```