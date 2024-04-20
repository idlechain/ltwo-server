import os
import json
import argparse
from eth_keys import keys
from eth_utils import decode_hex

def generate_ethereum_wallet():
    private_key = keys.PrivateKey(os.urandom(32))
    public_key_hex = private_key.public_key.to_hex()
    address = keys.PublicKey(decode_hex(public_key_hex)).to_address()
    private_key_hex = private_key.to_hex()
    return private_key_hex, address

def save_to_json(private_key):
    data = {"private_key": private_key, "port" : "9090"}
    with open("ltwo.json", "w") as f:
        json.dump(data, f)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="Generate JSON file")
    args = parser.parse_args()

    private_key, address = generate_ethereum_wallet()

    if args.json:
        if os.path.exists("ltwo.json"):
            print("Error: File 'ltwo.json' exists.")
        else:
            save_to_json(private_key)
            print("File 'ltwo.json' was created.")
    else:
        print("Private key:", private_key)
        print("Public address:", address)

if __name__ == "__main__":
    main()
