import bitcointools
from deserialize import parse_Transaction, opcodes
from BCDataStream import BCDataStream
from base58 import bc_address_to_hash_160, b58decode, public_key_to_bc_address, hash_160_to_bc_address

import ecdsa_ssl

import Crypto.Hash.SHA256 as sha256
import Crypto.Random


'''
Raw standard bitcoin transcation:

01000000

01
26c07ece0bce7cda0ccd14d99e205f118cde27e83dd75da7b141fe487b5528fb
00000000
8b
48304502202b7e37831273d74c8b5b1956c23e79acd660635a8d1063d413c50b218eb6bc8a022100a10a3a7b5aaa0f07827207daf81f718f51eeac96695cf1ef9f2020f21a0de02f01410452684bce6797a0a50d028e9632be0c2a7e5031b710972c2a3285520fb29fcd4ecfb5fc2bf86a1e7578e4f8a305eeb341d1c6fc0173e5837e2d3c7b178aade078
ffffffff

02

b06c191e01000000
19
76a9143564a74f9ddb4372301c49154605573d7d1a88fe88ac

00e1f50500000000
19
76a914010966776006953d5567439e5e39f86a0d273bee88ac
00000000

Private key:
18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725

'''

'''


In this answer, I will go through the steps necessary to redeem the second output of the transaction listed above. The answer will be limited to redeeming an output of the particular type present in this transaction (an output which requires providing a new transaction signed with a private key whose corresponding public key hashes to the hash in the script of the output in question), as this answer is already fairly long, even without taking into account other output types.

Short summary: We begin by constructing a new transaction, with a scriptSig containing the scriptPubKey of the output we want to redeem. The scriptPubKey of this transaction will contain a script that pays to a hash of a public key (Bitcoin address). We perform a double-SHA256 hash on this transaction with the four-byte hash code type SIGHASH_ALL appended to the end. We sign this hash with the private key supplied above. The scriptSig of this new transaction is then replaced with a script that first pushes the DER-encoded signature, plus the one-byte hash code type SIGHASH_ALL, to the stack, followed by the DER-encoded private key's corresponding public key.

Step-by-step description:

We start creating a new raw transaction which we hash and sign.

    Add four-byte version field: 01000000
    One-byte varint specifying the number of inputs: 01
    32-byte hash of the transaction from which we want to redeem an output: eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2
    Four-byte field denoting the output index we want to redeem from the transaction with the above hash (output number 2 = output index 1): 01000000
    Now comes the scriptSig. For the purpose of signing the transaction, this is temporarily filled with the scriptPubKey of the output we want to redeem. First we write a one-byte varint which denotes the length of the scriptSig (0x19 = 25 bytes): 19
    Then we write the temporary scriptSig which, again, is the scriptPubKey of the output we want to redeem: 76a914010966776006953d5567439e5e39f86a0d273bee88ac
    Then we write a four-byte field denoting the sequence. This is currently always set to 0xffffffff: ffffffff
    Next comes a one-byte varint containing the number of outputs in our new transaction. We will set this to 1 in this example: 01
    We then write an 8-byte field (64 bit integer) containing the amount we want to redeem from the specified output. I will set this to the total amount available in the output minus a fee of 0.001 BTC (0.999 BTC, or 99900000 Satoshis): 605af40500000000
    Then we start writing our transaction's output. We start with a one-byte varint denoting the length of the output script (0x19 or 25 bytes): 19
    Then the actual output script: 76a914097072524438d003d23a2f23edb65aae1bb3e46988ac
    Then we write the four-byte "lock time" field: 00000000

    And at last, we write a four-byte "hash code type" (1 in our case): 01000000

    We now have the following raw transaction data:
    
    01000000
01
eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2
01000000
19
76a914010966776006953d5567439e5e39f86a0d273bee88ac
ffffffff
01
605af40500000000
19
76a914097072524438d003d23a2f23edb65aae1bb3e46988ac
00000000
01000000

14. (signing stage) Now we double-SHA256 hash this entire structure, which yields the hash 
9302bda273a887cb40c13e02a50b4071a31fd3aae3ae04021b0b843dd61ad18e

15. We then create a public/private key pair out of the provided private key. We sign the hash 
from step 14 with the private key, which yields the following DER-encoded signature (this 
signature will be different in your case): 
30460221009e0339f72c793a89e664a8a932df073962a3f84eda0bd9e02084a6a9567f75aa022100bd9cbaca2e5ec
195751efdfac164b76250b1e21302e51ca86dd7ebd7020cdc06 

To this signature we append the one-byte hash code type: 01. The public key is: 
0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa
9e77237716103abc11a1df38855ed6f2ee187e9c582ba6


16. We construct the final scriptSig by concatenating:

    One-byte script OPCODE containing the length of the DER-encoded signature plus 1 (the length of the one-byte hash code type)
    The actual DER-encoded signature plus the one-byte hash code type
    One-byte script OPCODE containing the length of the public key
    The actual public key

17. We then replace the one-byte, varint length-field from step 5 with the length of the data from step 16. 
The length is 140 bytes, or 0x8C bytes: 8c

18.And we replace the temporary scriptSig from Step 6 with the data structure constructed in step 16. 
This becomes: 
4930460221009e0339f72c793a89e664a8a932df073962a3f84eda0bd9e02084a6a9567f75aa022100bd9
cbaca2e5ec195751efdfac164b76250b1e21302e51ca86dd7ebd7020cdc0601410450863ad64a87ae8a2f
e83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1d
f38855ed6f2ee187e9c582ba6

19. We finish off by removing the four-byte hash code type we added in step 13, and we 
end up with the following stream of bytes, which is the final transaction:

01000000
01
eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2
01000000
8c
4930460221009e0339f72c793a89e664a8a932df073962a3f84eda0bd9e02084a6a9567f75aa022100bd9cbaca2e5ec195751efdfac164b76250b1e21302e51ca86dd7ebd7020cdc0601410450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6
ffffffff
01
605af40500000000
19
76a914097072524438d003d23a2f23edb65aae1bb3e46988ac
00000000
'''


#transaction, from which we want to redeem an output
HEX_TRANSACTION="010000000126c07ece0bce7cda0ccd14d99e205f118cde27e83dd75da7b141fe487b5528fb000000008b48304502202b7e37831273d74c8b5b1956c23e79acd660635a8d1063d413c50b218eb6bc8a022100a10a3a7b5aaa0f07827207daf81f718f51eeac96695cf1ef9f2020f21a0de02f01410452684bce6797a0a50d028e9632be0c2a7e5031b710972c2a3285520fb29fcd4ecfb5fc2bf86a1e7578e4f8a305eeb341d1c6fc0173e5837e2d3c7b178aade078ffffffff02b06c191e010000001976a9143564a74f9ddb4372301c49154605573d7d1a88fe88ac00e1f505000000001976a914010966776006953d5567439e5e39f86a0d273bee88ac00000000"
#output to redeem. must exist in HEX_TRANSACTION
OUTPUT_INDEX=1
#address we want to send the redeemed coins to.
#REPLACE WITH YOUR OWN ADDRESS, unless you're feeling generous 
SEND_TO_ADDRESS="1L4xtXCdJNiYnyqE6UsB8KSJvqEuXjz6aK"
#fee we want to pay (in BTC)
TX_FEE=0.001
#constant that defines the number of Satoshis per BTC
COIN=100000000
#constant used to determine which part of the transaction is hashed.
SIGHASH_ALL=1
#private key whose public key hashes to the hash contained in scriptPubKey of output number *OUTPUT_INDEX* in the transaction described in HEX_TRANSACTION
PRIVATE_KEY=0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725

def dsha256(data):
   return sha256.new(sha256.new(data).digest()).digest()

tx_data=HEX_TRANSACTION.decode('hex_codec')
tx_hash=dsha256(tx_data)

#here we use bitcointools to parse a transaction. this gives easy access to the various fields of the transaction from which we want to redeem an output
stream = BCDataStream()
stream.write(tx_data)
tx_info = parse_Transaction(stream)

if len(tx_info['txOut']) < (OUTPUT_INDEX+1):
   raise RuntimeError, "there are only %d output(s) in the transaction you're trying to redeem from. you want to redeem output index %d" % (len(tx_info['txOut']), OUTPUT_INDEX)

#this dictionary is used to store the values of the various transaction fields
#  this is useful because we need to construct one transaction to hash and sign
#  and another that will be the final transaction
tx_fields = {}

##here we start creating the transaction that we hash and sign
sign_tx = BCDataStream()
##first we write the version number, which is 1
tx_fields['version'] = 1
sign_tx.write_int32(tx_fields['version'])
##then we write the number of transaction inputs, which is one
tx_fields['num_txin'] = 1
sign_tx.write_compact_size(tx_fields['num_txin'])

##then we write the actual transaction data
#'prevout_hash'
tx_fields['prevout_hash'] = tx_hash
sign_tx.write(tx_fields['prevout_hash']) #hash of the the transaction from which we want to redeem an output
#'prevout_n'
tx_fields['output_index'] = OUTPUT_INDEX
sign_tx.write_uint32(tx_fields['output_index']) #which output of the transaction with tx id 'prevout_hash' do we want to redeem?

##next comes the part of the transaction input. here we place the script of the *output* that we want to redeem
tx_fields['scriptSigHash'] = tx_info['txOut'][OUTPUT_INDEX]['scriptPubKey']
#first write the size
sign_tx.write_compact_size(len(tx_fields['scriptSigHash']))
#then the data
sign_tx.write(tx_fields['scriptSigHash'])

#'sequence'
tx_fields['sequence'] = 0xffffffff
sign_tx.write_uint32(tx_fields['sequence'])

##then we write the number of transaction outputs. we'll just use a single output in this example
tx_fields['num_txout'] = 1
sign_tx.write_compact_size(tx_fields['num_txout'])
##then we write the actual transaction output data
#we'll redeem everything from the original output minus TX_FEE
tx_fields['value'] = tx_info['txOut'][OUTPUT_INDEX]['value']-(TX_FEE*COIN)
sign_tx.write_int64(tx_fields['value'])
##this is where our scriptPubKey goes (a script that pays out to an address)
#we want the following script:
#"OP_DUP OP_HASH160  OP_EQUALVERIFY OP_CHECKSIG"
address_hash = bc_address_to_hash_160(SEND_TO_ADDRESS)
#chr(20) is the length of the address_hash (20 bytes or 160 bits)
scriptPubKey = chr(opcodes.OP_DUP) + chr(opcodes.OP_HASH160) + \
   chr(20) + address_hash + chr(opcodes.OP_EQUALVERIFY) + chr(opcodes.OP_CHECKSIG)
#first write the length of this lump of data
tx_fields['scriptPubKey'] = scriptPubKey
sign_tx.write_compact_size(len(tx_fields['scriptPubKey']))
#then the data
sign_tx.write(tx_fields['scriptPubKey'])

#write locktime (0)
tx_fields['locktime'] = 0
sign_tx.write_uint32(tx_fields['locktime'])
#and hash code type (1)
tx_fields['hash_type'] = SIGHASH_ALL
sign_tx.write_int32(tx_fields['hash_type'])

#then we obtain the hash of the signature-less transaction (the hash that we sign using our private key)
hash_scriptless = dsha256(sign_tx.input)

##now we begin with the ECDSA stuff.
## we create a private key from the provided private key data, and sign hash_scriptless with it
## we also check that the private key's corresponding public key can actually redeem the specified output

k = ecdsa_ssl.KEY()
k.generate(('%064x' % PRIVATE_KEY).decode('hex'))

#here we retrieve the public key data generated from the supplied private key
pubkey_data = k.get_pubkey()
#then we create a signature over the hash of the signature-less transaction
sig_data=k.sign(hash_scriptless)
#a one byte "hash type" is appended to the end of the signature (https://en.bitcoin.it/wiki/OP_CHECKSIG)
sig_data = sig_data + chr(SIGHASH_ALL)

#let's check that the provided privat key can actually redeem the output in question
if (bc_address_to_hash_160(public_key_to_bc_address(pubkey_data)) != tx_info['txOut'][OUTPUT_INDEX]['scriptPubKey'][3:-2]):
   bytes = b58decode(SEND_TO_ADDRESS, 25)
   raise RuntimeError, "The supplied private key cannot be used to redeem output index %d\nYou need to supply the private key for address %s" % \
                           (OUTPUT_INDEX, hash_160_to_bc_address(tx_info['txOut'][OUTPUT_INDEX]['scriptPubKey'][3:-2], bytes[0]))

##now we begin creating the final transaction. this is a duplicate of the signature-less transaction,
## with the scriptSig filled out with a script that pushes the signature plus one-byte hash code type, and public key from above, to the stack

final_tx = BCDataStream()
final_tx.write_int32(tx_fields['version'])
final_tx.write_compact_size(tx_fields['num_txin'])
final_tx.write(tx_fields['prevout_hash'])
final_tx.write_uint32(tx_fields['output_index'])

##now we need to write the actual scriptSig.
## this consists of the DER-encoded values r and s from the signature, a one-byte hash code type, and the public key in uncompressed format
## we also need to prepend the length of these two data pieces (encoded as a single byte
## containing the length), before each data piece. this length is a script opcode that tells the
## Bitcoin script interpreter to push the x following bytes onto the stack

scriptSig = chr(len(sig_data)) + sig_data + chr(len(pubkey_data)) + pubkey_data
#first write the length of this data
final_tx.write_compact_size(len(scriptSig))
#then the data
final_tx.write(scriptSig)

##and then we simply write the same data after the scriptSig that is in the signature-less transaction,
#  leaving out the four-byte hash code type (as this is encoded in the single byte following the signature data)

final_tx.write_uint32(tx_fields['sequence'])
final_tx.write_compact_size(tx_fields['num_txout'])
final_tx.write_int64(tx_fields['value'])
final_tx.write_compact_size(len(tx_fields['scriptPubKey']))
final_tx.write(tx_fields['scriptPubKey'])
final_tx.write_uint32(tx_fields['locktime'])

#prints out the final transaction in hex format (can be used as an argument to bitcoind's sendrawtransaction)
print final_tx.input.encode('hex')
