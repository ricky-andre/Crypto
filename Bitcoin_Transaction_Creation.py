import hashlib

# explaining how a transaction is built from the input transactions ...

'''
Total transaction information:
01000000018dd4f5fbd5e980fc02f35c6ce145935b11e284605bf599a13c6d415db55d07a1000000008b4830450221009908144ca6539e09512b9295c8a27050d478fbb96f8addbc3d075544dc41328702201aa528be2b907d316d2da068dd9eb1e23243d97e444d59290d2fddf25269ee0e0141042e930f39ba62c6534ee98ed20ca98959d34aa9e057cda01cfd422c6bab3667b76426529382c23f42b9b08d7832d4fee1d6b437a8526e59667ce9c4e9dcebcabbffffffff0200719a81860000001976a914df1bd49a6c9e34dfa8631f2c54cf39986027501b88ac009f0a5362000000434104cd5e9726e6afeae357b1806be25a4c3d3811775835d235417ea746b7db9eeab33cf01674b944c64561ce3388fa1abd0fa88b06c44ce81e2234aa70fe578d455dac00000000

Real example script in the blockchain, translating the above:

// decoded by https://blockchain.info/decode-tx
{
   "lock_time":0,
   "size":300,
   "inputs":[
      {
         "prev_out":{
            "index":0,
            "hash":"a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"
         },
         "script":"4830450221009908144ca6539e09512b9295c8a27050d478fbb96f8addbc3d075544dc41328702201aa528be2b907d316d2da068dd9eb1e23243d97e444d59290d2fddf25269ee0e0141042e930f39ba62c6534ee98ed20ca98959d34aa9e057cda01cfd422c6bab3667b76426529382c23f42b9b08d7832d4fee1d6b437a8526e59667ce9c4e9dcebcabb"
      }
   ],
   "version":1,
   "vin_sz":1,
   "hash":"cca7507897abc89628f450e8b1e0c6fca4ec3f7b34cccf55f3f531c659ff4d79",
   "vout_sz":2,
   "out":[
      {
         "script_string":"OP_DUP OP_HASH160 df1bd49a6c9e34dfa8631f2c54cf39986027501b OP_EQUALVERIFY OP_CHECKSIG",
         "address":"1MLh2UVHgonJY4ZtsakoXtkcXDJ2EPU6RY",
         "value":577700000000,
         "script":"76a914df1bd49a6c9e34dfa8631f2c54cf39986027501b88ac"
      },
      {
         "script_string":"04cd5e9726e6afeae357b1806be25a4c3d3811775835d235417ea746b7db9eeab33cf01674b944c64561ce3388fa1abd0fa88b06c44ce81e2234aa70fe578d455d OP_CHECKSIG",
         "address":"13TETb2WMr58mexBaNq1jmXV1J7Abk2tE2",
         "value":422300000000,
         "script":"4104cd5e9726e6afeae357b1806be25a4c3d3811775835d235417ea746b7db9eeab33cf01674b944c64561ce3388fa1abd0fa88b06c44ce81e2234aa70fe578d455dac"
      }
   ]
}


48  // push next 0x48 bytes
30450221009908144ca6539e09512b9295c8a27050d478fbb96f8addbc3d075544dc41328702201aa528be2b907d316d2da068dd9eb1e23243d97e444d59290d2fddf25269ee0e01
41  // push next 0x41 bytes, this is the Public Key, 66 bytes, "04"+Xpub+Ypub
042e930f39ba62c6534ee98ed20ca98959d34aa9e057cda01cfd422c6bab3667b76426529382c23f42b9b08d7832d4fee1d6b437a8526e59667ce9c4e9dcebcabb

First push is signature concatenated with hashtype=01 (SIGHASH_ALL)
Second push is public key for address 17SkEw2md5avVNyYgj6RiXuQKNwkXaxFyQ

1) Remove input script from transaction. We should remove bytes (do not forget about script len)

8b4830450221009908144ca6539e09512b9295c8a27050d478fbb96f8addbc3d
075544dc41328702201aa528be2b907d316d2da068dd9eb1e23243d97e444d59
290d2fddf25269ee0e0141042e930f39ba62c6534ee98ed20ca98959d34aa9e0
57cda01cfd422c6bab3667b76426529382c23f42b9b08d7832d4fee1d6b437a8
526e59667ce9c4e9dcebcabb

2) Replace it with the funding script to 17SkEw2md5avVNyYgj6RiXuQKNwkXaxFyQ

OP_DUP OP_HASH160 46af3fb481837fadbb421727f9959c2d32a36829 OP_EQUALVERIFY OP_CHECKSIG
1976a91446af3fb481837fadbb421727f9959c2d32a3682988ac

(Do not forget about script length again!)

3) Append SIGHASH_ALL as 32-bit low-endian value. The result will be

01000000018dd4f5fbd5e980fc02f35c6ce145935b11e284605bf599a13c6d41
5db55d07a1000000001976a91446af3fb481837fadbb421727f9959c2d32a368
2988acffffffff0200719a81860000001976a914df1bd49a6c9e34dfa8631f2c
54cf39986027501b88ac009f0a5362000000434104cd5e9726e6afeae357b180
6be25a4c3d3811775835d235417ea746b7db9eeab33cf01674b944c64561ce33
88fa1abd0fa88b06c44ce81e2234aa70fe578d455dac0000000001000000

4) Hash it twice by SHA256. The digest will be:
692678553d1b85ccf87d4d4443095f276cdf600f2bb7dd44f6effbd7458fd4c2

5) OK, we have now three items:

    a) public key 042e930f39ba62c6[...cut...]6e59667ce9c4e9dcebcabb
    b) signature 304502210099081[...cut...]d59290d2fddf25269ee0e
    c) digest 692678553d1b85ccf87d4d4443095f276cdf600f2bb7dd44f6effbd7458fd4c2

Pass these values to standard ECDSA verify method and you will receive the result: true or false. Here is a small piece of my quick-and-dirty check whith hardcoded values:

Now we can perform the signature calculation as described above, and check the output:

The output is:
"692678553d1b85ccf87d4d4443095f276cdf600f2bb7dd44f6effbd7458fd4c2"
"verify=1"

'''
