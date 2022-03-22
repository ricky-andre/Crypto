import hashlib

firstTransMessage = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff" \
"4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72" \
"206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff" \
"0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f" \
"61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"

# the hash has to be produced in this way, with sha256 called twice and the result
# must be save before running it for the second time. Beware to the little endian and
# big endian order of representation of the output.
# https://www.blockchain.com/it/btc/tx/4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
# The output is the following:
sha = hashlib.sha256()
sha.update(bytearray.fromhex(firstTransMessage))
out_hash = sha.hexdigest()
sha = hashlib.sha256()
sha.update(bytearray.fromhex(out_hash))
out_hash = sha.hexdigest()
print("Double SHA256 for the raw transaction:\n" + out_hash)

# ... and if you read it from the tail to the beginning, little endian conversion
out_hash = bytearray.fromhex(out_hash)
out_hash.reverse()
final_hash = ''.join(format(x, '02x') for x in out_hash)
print("\nReversed hash:\n" + final_hash)
