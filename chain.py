#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
from pymongo import MongoClient
import pymongo
import pyrx
import secrets
import struct
from Cryptodome.Util.number import long_to_bytes
import time
from web3 import Web3
import json
import datetime
import hashlib
from eth_account import Account, messages
from Crypto.Hash import keccak
import math
import traceback
from bson import json_util
import random
import string
import binascii
import sys
import rlp
from eth_typing import HexStr
from eth_utils import to_bytes, is_hex
from ethereum.transactions import Transaction
import threading
import requests
import socket
from decimal import Decimal

assert pyrx.__version__ >= '0.0.3'

# Coin definition
chain_name = "LTWO"
coin_ticker = "LTWO"
ltwoid = 7777000
idlechainid = 7777001
major_version = 1
minor_version = 0
coin_decimals = 1000000000000000000
pool_compat_decimals = 100000000
premining = 200000
blocktime = 60
base_diff = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
min_diff = 0
diff_retarget_blocks = 16
zero_hash = "0000000000000000000000000000000000000000000000000000000000000000"
initial_seed = "1200000000000000000000000000000000000000000000000000000000000012"
validator_frozen = 1000000000000000000000
# Wallet start
w3 = Web3()
sender_private_key = ''
sender_address = ''
chain_creator = '0xc5d29d659cedca813f8bc85e36e23ecf87b2023d'

#hardcoded contracts
null_address = "0x0000000000000000000000000000000000000000"
contract_validator = "0x0000000000000000000000000000000000000001"
contract_staking = "0x0000000000000000000000000000000000000002"

# Database definition
dbmongo = 'mongodb://127.0.0.1:27017'
client = MongoClient(dbmongo);
bcdb = client["ltwo"]
peers = bcdb["peers"]
blocks = bcdb["blocks"]
validators = bcdb["validators"]
txs = bcdb["transactions"]
mempool = bcdb["mempool"]
backup = bcdb["backup"]
logs = bcdb["logs"]
# Define the indexes
indices_blocks = [
    [("height", pymongo.ASCENDING)],
    [("hash", pymongo.ASCENDING)],
    [("timestamp", pymongo.ASCENDING)],
    [("prev_hash", pymongo.ASCENDING)],
]
indices_transactions = [
    [("_id", pymongo.ASCENDING)],
    [("block", pymongo.ASCENDING)],
    [("timestamp", pymongo.ASCENDING)],
    [("txinfo.hash", pymongo.ASCENDING)],
    [("txinfo.sender", pymongo.ASCENDING)],
    [("txinfo.to", pymongo.ASCENDING)],
    [("rawtx", pymongo.ASCENDING)],
    [("type", pymongo.ASCENDING)],
    [("txinfo.value", pymongo.ASCENDING)],
]

# Global variables
actualblock = 0
actualts = int(time.time())
open_sockets = {}
peer_threads = {}

def load_config(filename):
    global sender_private_key
    global sender_address
    try:
        with open(filename, "r") as file:
            data = json.load(file)
    except FileNotFoundError:
        print("Error: File " + str(filename) + " not exists")
        exit(1)
    except json.JSONDecodeError as e:
        print("Error: File " + str(filename) + " is not valid")
        exit(1)

    if 'private_key' not in data:
        print("Error: File " + str(filename) + " does not contains any private key")
        exit(1)

    try:
        sender_private_key = data['private_key']
        sender_account = Account.from_key(sender_private_key)
        sender_address = sender_account.address
    except Exception as e:
        print("Error: File " + str(filename) + " contains an invalid private key")
        exit(1)
    
    print(chain_name + " server started with address: " + sender_address)

def parse_tx_data(input_string):
    input_string = input_string[2:] if input_string.startswith('0x') else input_string
    method = input_string[:10]
    inputs = input_string[10:]
    inputs = [inputs[max(i-64, 0):i] for i in range(len(inputs), 0, -64)]
    inputs = [group.lstrip('0') for group in inputs]
    inputs.reverse()
    result = {
        'method': f'0x{method}',
        'inputs': inputs
    }
    return result
    
def format_tx_data(data, data_type):
    if data_type == 'eth_address':
        return '0x' + data.zfill(40)
    elif data_type == 'integer':
        return str(int(data, 16))
    elif data_type == 'string':
        return bytes.fromhex(data).decode('utf-8')
    else:
        return "0"

#start contracts test
def mint(tx):
    global null_address
    global chain_creator
    try:
        odata = parse_tx_data(tx.txinfo['data'])
        expected_method = '006d696e74'
        if odata['method'] == expected_method:
            if len(odata['inputs']) == 2:
                minter = chain_creator
                toaddr = format_tx_data(odata['inputs'][0], 'eth_address')
                value = format_tx_data(odata['inputs'][1], 'integer')
                if tx.txinfo['sender'] == miner and tx.txinfo['to'] == null_address and int(value) > 0:
                    internal_tx(null_address, toaddr, value, tx.rawtx, str(tx.get_chain_db()))
    except Exception as e:
        print("Error processing mintx")
        return False
    return True


def contract_type(address, chainid):
    if address == contract_staking:
        return 2
    elif address == contract_validator and chainid == ltwoid:
        return 1
    else:
        return 0

def staking_contract(tx):
    try:
        if tx.txinfo['data'] == '0x01' or tx.txinfo['data'] == '0x1':
            if contract_type(tx.txinfo['to'], tx.get_chain_db()) == 2:
                dbw = str(tx.get_chain_db()) + '_evmstorage'
                value = tx.txinfo['value']
                account = tx.txinfo['sender']
                db_evmstorage = bcdb[str(dbw)]
                staked = db_evmstorage.find_one({"account": account})
                if staked is None:
                    return True
                else:
                    returnvalue = int(staked["value"])
                    if returnvalue > 0:
                        db_evmstorage.delete_many({"account": account})
                        internal_tx(tx.txinfo['to'], tx.txinfo['sender'], returnvalue, tx.rawtx, str(tx.get_chain_db()))
        else:
            if contract_type(tx.txinfo['to'], tx.get_chain_db()) == 2:
                dbw = str(tx.get_chain_db()) + '_evmstorage'
                value = tx.txinfo['value']
                account = tx.txinfo['sender']
                db_evmstorage = bcdb[str(dbw)]
                staked = db_evmstorage.find_one({"account": account})
                if staked is None:
                    new_stake = {"account": account, "value": str(value)}
                    db_evmstorage.insert_one(new_stake)
                else:
                    new_value = int(staked["value"]) + int(value)
                    db_evmstorage.update_one({"account": account}, {"$set": {"value": str(new_value)}})
    except Exception as e:
        print("Error processing staking contract")
        return False
    return True
#end contracts test

def internal_tx(fromaddr, toaddr, value, rawtx, chainid):
    try:
        add_or_update_balance(fromaddr, value * -1, chainid)
        add_or_update_balance(toaddr, value, chainid)
        logs.insert_one({'rawtx':rawtx, 'event':'internaltx', 'sender':fromaddr, 'to':toaddr, 'value':str(value)})
        print("Internal tx sent")
    except Exception as e:
        print("Error processing internal tx")
        return False
    return True

def is_validator(address):
    result = validators.find_one({"address": address})
    return True if result else False

def create_indexes(collection, indexes):
    for index in indexes:
        try:
            collection.create_index(index, unique=False)
            print(f"Index {index} created successfully.")
        except pymongo.errors.OperationFailure:
            print(f"Index {index} already exists, not created.")

def peer_monitor():
    global actualts
    while True:
        try:
            new_peers = []
            for peer in peers.find():
                server = peer['ip']
                if server not in peer_threads:
                    new_thread = threading.Thread(target=launch_socket_client, args=(server,))
                    peer_threads[server] = new_thread
                    new_thread.start()
                    new_peers.append(server)
            if new_peers:
                print(f"New peers registered: {', '.join(new_peers)}")
            time.sleep(1)
        except Exception as e:
            time.sleep(1)

def socket_monitor_thread(client_thread, server):
    lastc = 0
    slastc = 300
    while True:
        try:
            if not client_thread.is_alive():
                lastc = slastc
                slastc = int(time.time())
                client_thread = threading.Thread(target=http_client, args=(server,))
                client_thread.start()
            if lastc + 10 > slastc:
                time.sleep(30)
            else:
                time.sleep(1)
        except Exception as e:
            time.sleep(2)

def launch_socket_client(server):
    client_thread = threading.Thread(target=http_client, args=(server,))
    client_thread.daemon = True
    client_thread.start()
    
    m_thread = threading.Thread(target=socket_monitor_thread, args=(client_thread,server,))
    m_thread.daemon = True
    m_thread.start()   

def register_peer(server):
    try:
        hdata = "ltwonetwork"
        url = "http://" + server + ":9090/registerpeer"
        response = requests.post(url, data=hdata, timeout=5)
        data = {
            'ip': server,
            'port': '9090',
            'status': 'ok'
        }
        mfilter = {'ip': server}
        peers.update_one(mfilter, {'$set': data}, upsert=True)
    except Exception as e:
        print("Unable to add peer: " + server)
    return

def http_client(server):
    global actualblock
    global actualts
    last_id = actualblock
    last_mempool = 0
    mempooltxs = 0
    mempooltimer = random.randint(0, blocktime)
    while True:
        try:
            t = int(time.time())
            if actualblock != last_id:
                hdata = str(actualblock)
                url = "http://" + server + ":9090/notifyblock"
                response = requests.post(url, data=hdata, timeout=5)
                last_id = actualblock
            if t != last_mempool and t % blocktime == int(mempooltimer):
                last_mempool = t
                mempooltxs = 0
                url = "http://" + server + ":9090/getmempool"
                response = requests.get(url, timeout=5)
                data = response.json()
                results = data['result']
                print(results)
                for tx in results:
                    mempooltxs += 1
                    hdata = str(tx['rawtx'])
                    url = "http://localhost:9090/addtransaction"
                    response = requests.post(url, data=hdata, timeout=2)
                    print(response)
                if mempooltxs > 0:
                    print("[worker] " + str(int(time.time())) +  " Mempool processed: " + str(mempooltxs) + " txs from " + str(server))
            time.sleep(0.5)
        except Exception as e:
            time.sleep(30)
            return

def rollback_block(height):
    print("[worker] " + str(int(time.time())) + " Rollback block: " + str(height))
    for txn in txs.find({"block": int(height)}):
        tx = Tx(txn['rawtx'])
        print(tx)
        add_or_update_balance(tx.txinfo['to'], int(tx.txinfo['value']) * -1, tx.get_chain_db())
        if int(txn['type']) > 1:
            add_or_update_balance(tx.txinfo['sender'], str((int(tx.txinfo['value']) + (int(tx.txinfo['gasprice'])*int(tx.txinfo['startgas'])))), tx.get_chain_db())
        print("[worker] " + str(int(time.time())) +  " Transacction removed: " + str(int(tx.txinfo['value'])/coin_decimals) + " " + coin_ticker + ", Hash: " + str(tx.txinfo['hash']))
        logs.delete_many({'hash': tx.txinfo['hash']})
        txs.delete_many({'rawtx': tx.rawtx})
    blocks.delete_many({'height': height})

def check_and_convert(data):
    if isinstance(data, bytes):
        data = data.decode('utf-8')
    return data

def hex_to_bytes(data: str) -> bytes:
    return to_bytes(hexstr=HexStr(data))

def is_valid_tx(raw_transaction):
    if not is_hex(raw_transaction):
        return False
    try:
        tx = rlp.decode(hex_to_bytes(raw_transaction), Transaction)
    except:
        return False
    return True

def add_or_update_balance(account, value, bid):
    account = account.lower()
    db_balances = bcdb[str(bid)]
    balance = db_balances.find_one({"account": account})
    if balance is None:
        new_balance = {"account": account, "value": str(value)}
        db_balances.insert_one(new_balance)
    else:
        new_value = int(balance["value"]) + int(value)
        db_balances.update_one({"account": account}, {"$set": {"value": str(new_value)}})

    return True

def to_byte_array(b):
    return [byte for byte in b]

def get_reward(height):
    if height == 2:
        reward = 100000
    else:
        reward = 1
    return reward

def pack_nonce(blob, nonce):
    b = binascii.unhexlify(blob)
    bin = struct.pack('39B', *bytearray(b[:39]))
    bin += struct.pack('I', nonce)
    bin += struct.pack('{}B'.format(len(b)-43), *bytearray(b[43:]))
    return bin

def compute_hash(b, n, s, h):
    seed = binascii.unhexlify(s);
    nonce = struct.unpack('I',binascii.unhexlify(n))[0]
    bin = pack_nonce(b, nonce)
    hex_hash = binascii.hexlify( pyrx.get_rx_hash(bin, seed, h) )
    return hex_hash

def sync_blockchain(force, server):
    previous_data = None
    global actualblock
    global actualts
    data = None
    theight = 0
    print("[worker] " + str(int(time.time())) +  " Syncing blockchain from " + server + "...")
    while True:
        z = blocks.find_one(sort=[("height", -1)])
        try:
            height = z['height']
            prevhash = z['hash']
        except:
            height = 0
            prevhash = zero_hash
           
        try:
            timestamp = int(z['timestamp'])
        except:
            timestamp = 0
        
        if force == 0:
            try:
                url = "http://" + server + ":9090/gettopblock"
                response = requests.get(url, timeout=5)
                data = response.json()
                theight = data['height']
            except ValueError as e:
                print("[worker] " + str(time.time()) + ", " + coin_ticker + " server connection error, retrying...");
                print(e)
            except Exception as e:
                print("[worker] " + str(time.time()) + ", " + coin_ticker + " server connection error, retrying...");
                print(e)
            
        try:
            if (data != previous_data and height < theight) or force == 1:
                hdata = str(height+1)
                url = "http://" + server + ":9090/getblocks"
                response = requests.post(url, data=hdata, timeout=5)
                data = response.json()
                results = data['result']
                for block in results:
                    if(prevhash == block['prev_hash'] and timestamp <= int(block['timestamp'])):
                        hblock = Block(block['height'], block['prev_hash'], block['transactions'], block['public_key'], int(block['timestamp']))
                        
                        #if 'sign' not in block:
                        #    block['sign'] = ''
                        
                        hblock.syncblock(block['hash'], block['nonce'], block['extranonce'], block['difficulty'], block['rewardtx'], block['sign'])
                        prevhash = block['hash']
                        actualblock = int(block['height'])
                        actualts = int(block['timestamp'])
                        if actualblock == 2:
                            #testnet missing tx fix (remove in mainnet) instead mint and internaltx
                            db_balances = bcdb['7777001']
                            new_balance = {"account": chain_creator, "value": "100000000000000000000000000"}
                            db_balances.insert_one(new_balance)
                        
                    else:
                        print("[worker] " + str(int(time.time())) +  " Invalid block found. Height: " + str(block['height']))
                        print(prevhash)
                        print(block['prev_hash'])
                        if height <= block['height']:
                            rollback_block(int(height))
                        break
                print("[worker] " + str(int(time.time())) +  " Block found and inserted. Height: " + str(block['height']))
                previous_data = data
                if force == 1:
                    break
            else:
                actualblock = int(height)-1
                actualts = int(time.time())
                print("[worker] " + str(int(time.time())) +  " Blockchain fully synced. Height: " + str(actualblock))
                break
        except ValueError as e:
            print("[worker] " + str(time.time()) + ", Sync error. Maybe blockchain is fully synced...");
            break
        except Exception as e:
            if force == 0:
                print(url)
                print("[worker] " + str(time.time()) + ", Peer error connection, closing connection..." + str(e))
            else:
                print("[worker] " + str(time.time()) + ", Blockchain fully synced")
            break

class Tx:
    def __init__(self, rawtx):
        self.rawtx = rawtx
        tx = rlp.decode(hex_to_bytes(self.rawtx), Transaction)
        self.txinfo = tx.to_dict()
        self.txinfo['value'] = str(self.txinfo['value'])
        self.txinfo['v'] = str(self.txinfo['v'])
        self.txinfo['r'] = str(self.txinfo['r'])
        self.txinfo['s'] = str(self.txinfo['s'])
        self.txinfo['sender'] = self.txinfo['sender'].lower()
        self.txinfo['to'] = self.txinfo['to'].lower()
        
    def is_validator_tx(self):
        if self.txinfo['to'] == '0x0000000000000000000000000000000000000001':
            if int(self.get_chain_db()) == int(ltwoid):
                if int(self.txinfo['value']) >= 1000000000000000000000:
                    validators.insert_one({'address': self.txinfo['sender'], 'block' : self.block,  'rawtx' : self.rawtx})
                    return True
                else:
                    return False
        return False
        
    def check_chain_id(self):
        if int(self.txinfo['v']) == 27 or int(self.txinfo['v']) == 28:
            chain_id = 0
        else:
            chain_id = int(self.txinfo['v']) - 35 >> 1
        return chain_id
        
    def get_chain_db(self):
        bid = self.check_chain_id()
        return str(bid)

    def add_to_mempool(self):
        if self.check_balance(self.get_chain_db()):
            if self.check_duplicate():
                return 0
            try:
                mempool.insert_one(self.__dict__)
                return 1
            except Exception as e:
                return -1
        else:
            return -2

    def check_duplicate(self):
        if mempool.find_one({'rawtx': self.rawtx}):
            return True
        if txs.find_one({'rawtx': self.rawtx}):
            return True
        return False

    def add_to_blockchain(self, checkbalance, block, timestamp):
        if txs.find_one({'rawtx': self.rawtx}):
            return False
        if checkbalance == 1:
            if self.check_balance(self.get_chain_db()) == True:
                try:
                    self.block = block
                    self.chainid = self.get_chain_db()
                    self.type = 2
                    self.timestamp = timestamp
                    txs.insert_one(self.__dict__)
                    self.is_validator_tx()
                    staking_contract(self)
                    mint(self)
                    return True
                except Exception as e:
                    print(e)
                    return False
            else:
                return False
        else:
            try:
                self.block = block
                self.chainid = self.get_chain_db()
                self.type = 1
                self.timestamp = timestamp
                txs.insert_one(self.__dict__)
                return True
            except Exception as e:
                print(e)
                return False
        
    def check_balance(self, bid):
        db_balances = bcdb[str(bid)]
        balance = db_balances.find_one({"account": self.txinfo['sender']})
        if balance is None:
            new_balance = {"account": self.txinfo['sender'], "value": "0"}
            db_balances.insert_one(new_balance)
            return False
        else:
            sender_balance = int(balance["value"])
            if sender_balance >= int(self.txinfo['value']) + (int(self.txinfo['gasprice'])*int(self.txinfo['startgas'])):
                return True
            else:
                return False

class Block:
    def __init__(self, height, prev_hash, transactions, public_key, timestamp):
        self.height = height
        self.prev_hash = prev_hash        
        self.timestamp = int(timestamp)
        self.transactions = transactions
        self.rewardtx = None
        self.public_key = public_key
        self.difficulty = self.get_diff()
        self.nonce = None
        self.extranonce = None
        self.version = "0101"

    def get_reward(self):
        if self.height == 2:
            reward = 100000
        else:
            reward = 1
        return reward
        
    def process_mempool(self):
        processed = 0
        duplicated = 0
        pvalue = 0
        dvalue = 0
        for txn in mempool.find():
            try:
                tx = Tx(txn['rawtx'])
                if tx.check_chain_id() != ltwoid and tx.check_chain_id() != idlechainid:
                        raise ValueError("Invalid ChainId")
                        
                if tx.check_balance(tx.get_chain_db()) == True:
                    rn = tx.add_to_blockchain(1, self.height, self.timestamp)
                    if rn == True:
                        self.transactions.append(tx.rawtx)
                        add_or_update_balance(tx.txinfo['to'], tx.txinfo['value'], tx.get_chain_db())
                        add_or_update_balance(tx.txinfo['sender'], str((int(tx.txinfo['value']) + (int(tx.txinfo['gasprice'])*int(tx.txinfo['startgas']))) * -1), tx.get_chain_db())
                        processed += 1
                        pvalue += int(tx.txinfo['value'])
                        log = {"tx": str(tx.txinfo['hash']), "block": self.height, "status": "ok", "action": "inserted"}
                        logs.insert_one(log)
                    else:
                        duplicated += 1
                        dvalue += int(tx.txinfo['value'])
                        log = {"tx": str(tx.txinfo['hash']), "block": self.height, "status": "duplicated", "action": "reverted"}
                        logs.insert_one(log)
                    mempool.delete_many({'rawtx': tx.rawtx})
            except:
                mempool.delete_many({'rawtx': tx.rawtx})
        mempool.delete_many({})
        if processed > 0:
            print("[miner] " + str(int(time.time())) +  " Transacction processed: " + str(processed) + ", Total value: " + str(int(pvalue)/coin_decimals) + " " + coin_ticker)
        if duplicated > 0:
            print("[miner] " + str(int(time.time())) +  " Transacction not processed: " + str(duplicated) + ", Total value: " + str(int(dvalue)/coin_decimals) + " " + coin_ticker)

    def get_diff(self):
        if self.height > diff_retarget_blocks:
            a = blocks.find(sort=[("height", -1)]).limit(diff_retarget_blocks)
            dsum = sum(doc["difficulty"] for doc in a)
            dsum = math.ceil(dsum / diff_retarget_blocks)
            z = blocks.find(sort=[("height", -1)]).limit(diff_retarget_blocks)
            t = abs(z[diff_retarget_blocks-1]["timestamp"] - z[0]["timestamp"])
            
            if t > 0:
                diff = math.ceil((dsum*diff_retarget_blocks*blocktime)/t)
            else:
                diff = min_diff
                
            if diff < min_diff:
                diff = min_diff
        else:
            diff = min_diff
        #return diff
        return 0
        
    def get_seed(self):
        if(math.floor(self.height/1024) == 0):
            seed = initial_seed
        else:
            seed = initial_seed
        return seed
    
    def get_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        h = hashlib.sha512(block_string.encode())
        hash_hex = h.hexdigest()
        return hash_hex[:64]

    def create_reward_transaction(self):
        txnonce = self.height
        txvalue = w3.to_wei(self.get_reward(), 'ether')
        tx = {
            'nonce': txnonce,
            'to': self.public_key,
            'value': txvalue,
            'gas': 1,
            'gasPrice': w3.to_wei('0', 'gwei'),
            'chainId' : ltwoid
        }
        signed_tx = w3.eth.account.sign_transaction(tx, sender_private_key)
        signedtx = signed_tx.hash.hex()[2:]
        self.rewardtx = signed_tx.rawTransaction.hex()
        return signedtx
        
    def get_blob(self):
        seed = self.get_seed()
        seed = binascii.unhexlify(seed);
        hdiff = hex(self.difficulty)[2:].zfill(10)
        rewardhash = self.create_reward_transaction()
        blob = "0000" + self.prev_hash + hdiff + "00000000" + rewardhash
        return blob
        
    def syncblock(self, blockhash, nonce, extranonce, difficulty, rewardtx, sign):
        processed = 0
        duplicated = 0
        pvalue = 0
        dvalue = 0
        self.nonce = nonce
        self.extranonce = extranonce
        self.rewardtx = rewardtx
        self.sign = sign
        
        #if int(self.get_diff()) == int(difficulty):
        #    self.difficulty = difficulty
        self.difficulty = difficulty
        #else:
        #    print("[miner] " + str(int(time.time())) +  " Invalid block difficulty, can't sync with this blockchain")
        #    return

        rwtxa = Tx(self.rewardtx)
        #expectedreward = w3.to_wei(self.get_reward(), 'ether')
        #if int(rwtxa.txinfo['value']) != int(expectedreward):
        #    print("[miner] " + str(int(time.time())) +  " Invalid reward value, can't sync with this blockchain")
        #    return
            
        #if self.sign_verify == False:
        #    print("[miner] " + str(int(time.time())) +  " Invalid block signature, can't sync with this blockchain")
        #    return
        
        seed = self.get_seed()
        hdiff = hex(self.difficulty)[2:].zfill(10)
        rewardhash = rwtxa.txinfo['hash'][2:]
        blob = self.extranonce + self.prev_hash + hdiff + "00000000" + rewardhash
        if self.difficulty > 0:
            hex_hash = compute_hash(blob, nonce, seed, self.height)
            hash_bytes = bytes.fromhex(hex_hash.decode())
            hash_array = to_byte_array(hash_bytes)[::-1]
            hash_num = int.from_bytes(bytes(hash_array), byteorder='big')
            hash_diff = base_diff / hash_num
            if hash_diff < self.difficulty:
                print("[miner] " + str(int(time.time())) +  " Invalid nonce, block difficulty too low, can't sync with this blockchain")
                return

        rwtxn = rwtxa.add_to_blockchain(0, self.height, self.timestamp)
        add_or_update_balance(self.public_key, str(w3.to_wei(self.get_reward(), 'ether')), rwtxa.get_chain_db())
        self.hash = blockhash
        for txn in self.transactions:
            tx = Tx(txn)
            if tx.check_chain_id() != ltwoid and tx.check_chain_id() != idlechainid:
                #raise ValueError("Invalid ChainId")
                mempool.delete_many({'rawtx': tx.rawtx})
                continue

            if tx.check_balance(tx.get_chain_db()) == True:
                rn = tx.add_to_blockchain(1, self.height, self.timestamp)
                if rn == True:
                    add_or_update_balance(tx.txinfo['to'], tx.txinfo['value'], tx.get_chain_db())
                    add_or_update_balance(tx.txinfo['sender'], str((int(tx.txinfo['value']) + (int(tx.txinfo['gasprice'])*int(tx.txinfo['startgas']))) * -1), tx.get_chain_db())
                    processed += 1
                    pvalue += int(tx.txinfo['value'])
                    log = {"tx": str(tx.txinfo['hash']), "block": self.height, "status": "ok", "action": "inserted"}
                    logs.insert_one(log)
                else:
                    duplicated += 1
                    dvalue += int(tx.txinfo['value'])
                    log = {"tx": str(tx.txinfo['hash']), "block": self.height, "status": "duplicated", "action": "reverted"}
                    logs.insert_one(log)
                mempool.delete_many({'rawtx': tx.rawtx})
        if processed > 0:
            print("[miner] " + str(int(time.time())) +  " Transacction processed: " + str(processed) + ", Total value: " + str(int(pvalue)/coin_decimals) + " " + coin_ticker)
        if duplicated > 0:
            print("[miner] " + str(int(time.time())) +  " Transacction not processed: " + str(duplicated) + ", Total value: " + str(int(dvalue)/coin_decimals) + " " + coin_ticker)

        self.add_to_db()

    def mine(self, nonce, extranonce):
        self.nonce = nonce
        self.extranonce = extranonce
        seed = self.get_seed()
        hdiff = hex(self.difficulty)[2:].zfill(10)
        rewardhash = self.create_reward_transaction()
        blob = self.extranonce + self.prev_hash + hdiff + "00000000" + rewardhash
        hex_hash = compute_hash(blob, nonce, seed, self.height)
        hash_bytes = bytes.fromhex(hex_hash.decode())
        hash_array = to_byte_array(hash_bytes)[::-1]
        hash_num = int.from_bytes(bytes(hash_array), byteorder='big')
        hash_diff = base_diff / hash_num
        if hash_diff >= self.difficulty:
            self.process_mempool()
            rwtxa = Tx(self.rewardtx)
            rwtxn = rwtxa.add_to_blockchain(0, self.height, self.timestamp)
            block_hash = self.get_hash()
            self.hash = block_hash
            self.sign_block()
            self.add_to_db()
            add_or_update_balance(self.public_key, str(w3.to_wei(self.get_reward(), 'ether')), ltwoid)
            return True
        else:
            return False

    def sign_block(self):
        try:
            block_string = json.dumps(self.__dict__, sort_keys=True)
            block_hash = hashlib.sha3_256(block_string.encode()).hexdigest()
            message = messages.encode_defunct(hexstr=block_hash)
            signed_block = Account.sign_message(message, private_key=sender_private_key)
            self.sign = signed_block.signature.hex()
        except Exception as e:
            print(e)
            traceback.print_exc()

    def sign_verify(self):
        try:
            pkey = self.public_key
            signature_hash = self.sign
            try:
                del self.sign
            except:
                pass
            try:
                del self._id
            except:
                pass
            print(signature_hash)
            block_string = json.dumps(self.__dict__, sort_keys=True)
            block_hash = hashlib.sha3_256(block_string.encode()).hexdigest()
            message = messages.encode_defunct(hexstr=block_hash)
            is_valid = Account.recover_message(message, signature=signature_hash) == pkey
            if is_valid:
                self.sign = signature_hash
            return is_valid
        except Exception as e:
            print(e)
            traceback.print_exc()

    def add_to_db(self):
        blocks.insert_one(self.__dict__)

class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()


    def do_GET(self):
        global actualblock
        global actualts
        if str(self.path) == "/gettopblock":
            self._set_response()
            resp = '{"version": "1.0", "height": ' + str(actualblock) + '}'
            self.wfile.write(resp.encode('utf-8'))
        if str(self.path) == "/getmempool":
            self._set_response()
            results = mempool.find()
            result_list = []
            for result in results:
                result_list.append(result)
            json_output = json.loads(json_util.dumps({"id": 1, "status": "ok", "result": result_list}))
            print(json.dumps(json_output))
            self.wfile.write(json.dumps(json_output).encode('utf-8'))

    def do_POST(self):
        global actualblock
        global actualts
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        if str(self.path) == "/json_rpc":
            post_data = post_data.decode('utf-8')
            post_data = json.loads(post_data)
            print("Json request: " + post_data["method"])
            self._set_response()
            if post_data["method"] == "submitblock":
                z = blocks.find_one(sort=[("height", -1)])
                try:
                    height = z['height']+1
                    prevhash = z['hash']
                except:
                    height = 1
                    prevhash = zero_hash
                try:
                    timestamp = int(z['timestamp'])+1
                except:
                    timestamp = int(time.time())
                rawnonce = post_data["params"][0]
                transactions = []

                block = Block(height, prevhash, transactions, sender_address, datetime.datetime.now().timestamp())
                extranonce = rawnonce[:4]
                nonce = rawnonce[-8:]
                rt = block.mine(nonce, extranonce)
                if rt == True:
                    actualblock = block.height
                    actualts = int(block.timestamp)
                    self.wfile.write(('{"id" : "1", "jsonrpc" : "2.0", "result" : { "status": "OK", "hash": "' + str(block.hash) + '"} }').encode('utf-8'))
                    print("[miner] " + str(int(time.time())) +  " New block found! Height:  " + str(block.height) + ", Difficulty: " + str(block.difficulty) + ", Extranonce: " + str(block.extranonce) + ", Nonce: " + str(block.nonce))
                else:
                    self.wfile.write('{"id" : "1", "jsonrpc" : "2.0", "error" : {"code" : "-7", "message": "Block not accepted"} }'.encode('utf-8'))
            else:
                print(post_data["method"])
                self.wfile.write("{status: 'ok'}".encode('utf-8'))
                
        if str(self.path) == "/registerpeer":
            post_data = post_data.decode('utf-8')
            self._set_response()
            self.wfile.write("{status: 'ok'}".encode('utf-8'))
            if post_data == "ltwonetwork":
                data = {
                    'ip': str(self.client_address[0]),
                    'port': '9090',
                    'status': 'ok'
                }
                mfilter = {'ip': str(self.client_address[0])}
                peers.update_one(mfilter, {'$set': data}, upsert=True)
        if str(self.path) == "/notifyblock":
            post_data = post_data.decode('utf-8')
            block = int(post_data)
            self._set_response()
            self.wfile.write("{status: 'ok'}".encode('utf-8'))
            if actualblock < block:
                sync_blockchain(1, self.client_address[0])
        if str(self.path) == "/syncbc":
            post_data = post_data.decode('utf-8')
            self._set_response()
            self.wfile.write("{status: 'ok'}".encode('utf-8'))
            sync_blockchain(1, post_data)
        if str(self.path) == "/getblocks":
            post_data = post_data.decode('utf-8')
            self._set_response()
            results = blocks.find({"height": {"$gte": int(post_data)}}).limit(200)
            result_list = []
            for result in results:
                result_list.append(result)
            json_output = json.loads(json_util.dumps({"id": 1, "status": "ok", "result": result_list}))
            self.wfile.write(json.dumps(json_output).encode('utf-8'))
        if str(self.path) == "/addtransaction":
            self._set_response()
            post_data = post_data.decode('utf-8')
            print(post_data)
            try:
                tx = Tx(post_data)
                if tx.check_chain_id() != ltwoid and tx.check_chain_id() != idlechainid:
                    raise ValueError("Invalid ChainId")
                n = is_valid_tx(post_data)
                if n == True:
                    rn = tx.add_to_mempool()
                    if rn == 1:
                        print("Transaction accepted")
                        self.wfile.write(('{"id": "0", "jsonrpc": "2.0", "result": {"status": "OK", "tx_hash" : "'  + str(tx.txinfo['hash']) + '"} }').encode('utf-8'))
                    elif rn == -1 or rn == -2:
                        print("Transaction duplicated")
                        self.wfile.write('{"status": "error"}'.encode('utf-8'))
                    elif rn == 0:
                        print("Transaction accepted")
                        self.wfile.write(('{"id": "0", "jsonrpc": "2.0", "result": {"status": "OK", "tx_hash" : "'  + str(tx.txinfo['hash']) + '"} }').encode('utf-8'))
                else:
                    print("Invalid transaction")
                    self.wfile.write('{"status": "error"}'.encode('utf-8'))
            except Exception as e:
                print("Transaction error: ", e)
                self.wfile.write('{"status": "error"}'.encode('utf-8'))

def run(server_class=HTTPServer, handler_class=S, port=9090):
    logging.basicConfig(level=logging.WARNING)
    server_address = ('0.0.0.0', port)
    httpd = server_class(server_address, handler_class)
    print("[worker] " + str(int(time.time())) + 'Starting httpd...')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print("[worker] " + str(int(time.time())) +  'Stopping httpd...')

def chain_start():
    create_indexes(blocks, indices_blocks)
    create_indexes(txs, indices_transactions)

    load_config('ltwo.json')
    
    try:
        register_peer("ltwo.idlecalypse.cc")
    except Exception as e:
        print(e)
    
    for peer in peers.find():
        server = peer['ip']
        sync_blockchain(0, server)
    
    http_monitor = threading.Thread(target=peer_monitor)
    http_monitor.daemon = True
    http_monitor.start()
    
    run()

chain_start()
