# ltwo-server
LTWO server implementation in Python one file

## Installation on Ubuntu

### Installing MongoDB
https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu/

### Dependencies
After installing MongoDB, follow these steps:

```bash
sudo apt-get update
sudo apt-get install python3-pip git cmake screen
pip3 install pymongo pycryptodomex web3 ethereum==2.3.2 rlp==1.2.0
pip3 install git+https://github.com/idlechain/pyrx
```

### Configuration
Run createaddress.py for create new address and store the private key in 'ltwo.json', then launch the server.

```bash
git clone https://github.com/idlechain/ltwo-server
cd ltwo-server
python3 createaddress.py --json
```

### Running the server
Currently, the program cannot function as a daemon. Therefore, it is best to run it within a screen session:

```bash
screen
python3 chain.py
```
