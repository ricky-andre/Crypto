import hashlib
import requests
import json
from os import path

# we retrieve the data related to a block of transactions in the blockchain,
# this is simply performed through an http query, of the following type:
#
# req = requests.get('https://blockchain.info/rawblock/$hash_block_value')
#
# Data is retrieved in json format, the above can be also configured into Firefox,
# and data is available in text format, or "surfable". Check it out !!
#
# We parse all the hashes of all transactions (there can be thousands of transactions),
# and calculate the merkle root hash through the bitcoin algorithm.


# beware to the big endian and little endian problem ...
def hash_calc(msg):
    # in bitcoin's merkle trees, SHA256 is applied twice (known as double-SHA256).
    sha = hashlib.sha256()
    sha.update(bytearray.fromhex(msg))
    temp_hash = sha.hexdigest()
    sha = hashlib.sha256()
    sha.update(bytearray.fromhex(temp_hash))
    return sha.hexdigest()

# The algorithm works as follows. Once the hashes have been reverted into big endian
# from the data retrieved from the blockchain info, we have for example 12 transactions
# Exactly in the order with which they are received, we calculate the following:
#
# SHA256(SHA256(hash(1)+hash(2)))    ---> hash(13)
# ...
# SHA256(SHA256(hash(11)+hash(12)))  ----> hash(18)
#
# We go on with the second cycle and do the following:
# SHA256(SHA256(hash(13)+hash(14)))    ---> hash(19)
# ...
# SHA256(SHA256(hash(17)+hash(18)))  ----> hash(21)
#
# ... we now have just 3 leaves, so the last leaf is DUPLICATED, and we generate
# two more hashes for the algorithm to proceed:
# SHA256(SHA256(hash(19)+hash(20)))  ----> hash(23)
# SHA256(SHA256(hash(21)+hash(21)))  ----> hash(24)
#
# and now the last step:
# SHA256(SHA256(hash(23)+hash(24)))  ----> hash(25) MERKLE ROOT HASH
def generate_merkle_root(q):
    # if number of transactions is odd, duplicate last transaction
    n_transactions = len(q)
    if n_transactions % 2 == 1:
        q.append(q[n_transactions - 1])
    # new array to store the calculated hashes
    p = []
    while len(q) > 1:
        # take the first two hashes in the list, calculate the hash of the sum
        # and append it to the end of the queue
        a, b = q.pop(0), q.pop(0)
        # beware that this operations concatenates the two hashes into a 64-long hex string
        c = hash_calc(a + b)
        p.append(c)
    # in case the number of calculated hashes is bigger than 2, we call recursively
    # this function and return the new calculated value
    if len(p)>1:
        return generate_merkle_root(p)
    return p[0]

# We retrieve the raw transaction file from blockchain, and save it to disk.
# The second time, we read it from disk to be faster, in case we want to re-download it,
# we can of course cancel the file on disk.
if (path.exists("C:/Users/601787621/desktop/blockchain_block.json")):
    with open("C:/Users/601787621/desktop/blockchain_block.json", "r") as read_file:
        data = json.load(read_file)
else:
    req = requests.get('https://blockchain.info/rawblock/000000000000000000155a0c59bfdb54834608e7bf55e29920fd24591f1e3a98')
    # for debugging this one has only 4 transactions ...
    #req = requests.get('https://blockchain.info/rawblock/000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506')
    #print (r.json())
    data = req.json()
    with open("C:/Users/601787621/desktop/blockchain_block.json", "w") as write_file:
        json.dump(req.json(), write_file)


txHashes = []
# we need to transform everything in big endian to avoid algorith problems
for elem in data['tx']:
    #txHashes.append(elem['hash'])
    out_hash = bytearray.fromhex(elem['hash'])
    out_hash.reverse()
    reversed_hash = ''.join(format(x, '02x') for x in out_hash)
    txHashes.append(reversed_hash)

print("In this block there are " + str(len(txHashes)) + " transactions.\n")
print ("Merkle root from blockchain data:\n" + data['mrkl_root'] + "\n")

merkle_root_big = generate_merkle_root(txHashes)
out_hash = bytearray.fromhex(merkle_root_big)
out_hash.reverse()
merkle_root = ''.join(format(x, '02x') for x in out_hash)
print ("Calculated merkle root:\n" + merkle_root)
