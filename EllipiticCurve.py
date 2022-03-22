import hashlib
import base58

# The proven prime
Pcurve = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1
# These two defines the elliptic curve. y^2 = x^3 + Acurve * x + Bcurve
Acurve = 0; Bcurve = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
# Generator Point
GPoint = (Gx,Gy)
# Number of points in the field
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# hex version of the key below, to put it inside www.bitaddress.org
# privKey = 0xa665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3
privKey = 75263518707598184987916378021939673586055614731957507592904438851787542395619


# replace with a truly random number, for every new signature to be generated, this prime
# number MUST be changed, this is important ... otherwise two signatures can be used to retrieve
# the private key !!!
RandNum = 28695618543805844332113829720373285210420739438570883203839696518176414791234
# in the bitcoin world, the message to be hashed is that of the transaction, of course WITHOUT
# the signature. In place of the signature in the message is used the scriptPubKey of the
# output transaction we are referring to. See the following site for more information.
# https://klmoney.wordpress.com/bitcoin-dissecting-transactions-part-2-building-a-transaction-by-hand/
# the hash of your message/transaction
HashOfThingToSign = 86032112319101611046176971828093669637772856272773459297323797145286374828050 

# Extended Euclidean Algorithm/'division' in elliptic curves. Dividing a number
# in the "mod(p)" world where p is a prime number, means to multiply for the inverse
# of that number:
# a/b = a * b^(-1) 
# b elevated to (-1) or b^(-1) is the number that multiplied by b, gives "1 mod(p)".
# It can be calculated with a logaritmic speed algorithm, called "extended euclidean algorithm"
# https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
def modinv(a,b=Pcurve):
    lm, hm = 1,0
    low, high = a%b,b
    while low > 1:
        ratio = high//low
        nm, new = hm-lm*ratio, high-low*ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % b

# Point addition, invented for EC.
def ECAdd(a,b):
    LambdaAdd = ((b[1] - a[1]) * modinv(b[0] - a[0],Pcurve)) % Pcurve
    x = (LambdaAdd * LambdaAdd - a[0] - b[0]) % Pcurve
    y = (LambdaAdd * (a[0] - x) - a[1]) % Pcurve
    return (x,y)

# Point Doubling, also invented for EC.
def ECDouble(a):
    LamdaDouble = ((3 * a[0] * a[0] + Acurve) * modinv((2 * a[1]), Pcurve)) % Pcurve
    x = (LamdaDouble * LamdaDouble - 2 * a[0]) % Pcurve
    y = (LamdaDouble * (a[0] - x) - a[1]) % Pcurve
    return (x,y)

#Double & add. Not true multiplication
def ECMultiply(GenPoint,privKeyHex):
    if privKeyHex == 0 or privKeyHex >= N: raise Exception("Invalid Private Key")
    privKeyBin = str(bin(privKeyHex))[2:]
    Q=GenPoint
    for i in range (1, len(privKeyBin)):
        Q=ECDouble(Q);
        if privKeyBin[i] == "1":
            Q=ECAdd(Q,GenPoint);
    return (Q)

# executing the ripemd160 function
def hash160(hex_str):
    sha = hashlib.sha256()
    rip = hashlib.new('ripemd160')
    sha.update(hex_str)
    rip.update( sha.digest() )
    # also returns an hex string
    return rip.hexdigest()

# the bitcoin address is obtained from the public key as explained here:
# https://en.bitcoin.it/wiki/Address
#
# basicly it's '00' + hash160(key) + checksum
#
# checksum is obtained from calculating two times the sha256 of:
# '00'+hash160(key)
# and taking the most significant 4 bytes or 8 hex digits
def getBitcoinAddress (hexPublicKey):
    # Obtain key, hex format:
    key_hash = '00' + hash160(bytearray.fromhex(hexPublicKey))
    # Obtain signature:
    sha = hashlib.sha256()
    sha.update(bytearray.fromhex(key_hash))
    checksum = sha.digest()
    sha = hashlib.sha256()
    sha.update(checksum)
    checksum = sha.hexdigest()[0:8]
    #print ( "checksum = \t\t" + sha.hexdigest())
    #print ( "key_hash + checksum = \t" + key_hash + ' ' + checksum )
    return (base58.b58encode(bytes(bytearray.fromhex(key_hash + checksum)))).decode('utf-8')

PublicKey = ECMultiply(GPoint,privKey)
# 66 hex digits for the public key
fullHexPublicKey = "04"+str(hex(PublicKey[0]))[2:]+str(hex(PublicKey[1]))[2:]
print("Private Key:")
print (privKey)
print("Private Key (hex), check it on www.bitaddress.com:")
print (hex(privKey))
print("\nPublic Key public key (uncompressed):")
print ("04", PublicKey)
print("\nPublic Key (compressed):")
if (PublicKey[1] % 2 == 1): # If the Y coordinate of the Public Key is odd.
    compressedPublicKey = "03" + str(hex(PublicKey[0])[2:]).zfill(64)
else: # If the Y coordinate is even.
    compressedPublicKey = "02" + str(hex(PublicKey[0])[2:]).zfill(64)
print(compressedPublicKey + "\n")

compressedBitcoinAddress = getBitcoinAddress(compressedPublicKey)
bitcoinAddress = getBitcoinAddress("04"+str(hex(PublicKey[0]))[2:]+str(hex(PublicKey[1]))[2:])
print("Compressed bitcoin address:\t\t" + compressedBitcoinAddress)
print("Bitcoin address:\t\t\t" + bitcoinAddress)


# it is extremely important that the random number is being generated EVERY time
# a new signature is generated. In case the same number is used, from a couple of
# outputs the private key can be calculated. Of course in the calculation the private
# key is used, but not communicated to anyone.
print("\n******* Signature Generation *******")
xRandSignPoint, yRandSignPoint = ECMultiply(GPoint,RandNum)
r = xRandSignPoint % N
print("r =", r)
s = ((HashOfThingToSign + r*privKey)*(modinv(RandNum,N))) % N
print("s =", s)


# this is the verification of the signature, anyone can do it without knowing the private key,
# but just knowing the signature (r,s) and the message that was signed, or better
# the HASH that was used to sign the message. HashOfThingToSign is known, (r,s) is known,
# the PublicKey is known, GPoint and N are known.
print("\n******* Signature Verification ********>>")
w = modinv(s,N)
x, y = ECAdd(ECMultiply(GPoint,(HashOfThingToSign * w) % N), ECMultiply(PublicKey,(r*w) % N))
print(r==x);


# We now want to calculate two signatures from two different messages hashes, and from the
# output we want to retrieve the private key. As previously explained, the randomKey MUST
# be changed every time a new signature is generated, otherwise this is what happens !!
HashOfThingToSign_2 = 860321229856752856272773459297323797145286374828050
print("\n******* Signature 2 Generation *******")
xRandSignPoint, yRandSignPoint = ECMultiply(GPoint,RandNum)
r_2 = xRandSignPoint % N
# this is goint to be the same respect to r
print("r =", r_2)
s_2 = ((HashOfThingToSign_2 + r_2*privKey)*(modinv(RandNum,N))) % N
print("s =", s_2)



# We know (r,s) generated from the hash of the message to be signed,
# and (r_1, s_1) from hash_2. From here:
# https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
#
# Since by definition (k is the randomKey):
#
# s = k^(-1)*(hash+r*privKey)
# s' = k^(-1)*(hash'+r'*privKey)
# 
# Let's remember also that r = randKey*G, if the randKey is not changed we
# have that r = r' and r-r' = 0
#
# We multiply both equations on the left for k, and than subtract the two:
#
# k*s = (hash+r*privKey)
# k*s' = (hash'+r'*privKey)
#
# k*s-k*s' = hash-hash'+(r-r')*privKey = hash-hash'
# k*(s-s') = hash-hash'
# k = (hash-hash')/(s-s')
num = (HashOfThingToSign - HashOfThingToSign_2) % N
den = modinv(s-s_2,N) % N
rand_key = (num * den) % N
print ("\nRetrieved random key from both signatures:\n"+str(rand_key))

# By definition again, we have that:
# s = k^(-1)*(hash+r*privKey)
# k*s = hash+r*privKey
# k*s - hash = r*privKey
# privKey = (k*s - hash)/r
num = (s*rand_key - HashOfThingToSign) % N
den = modinv(r, N)
priv_key = (num * den) % N
print ("\nRetrieved private key from second signature:\n"+str(priv_key))

# or equivalently
num = (s_2*rand_key - HashOfThingToSign_2) % N
den = modinv(r_2, N)
priv_key = (num * den) % N
print ("Retrieved private key from second signature:\n"+str(priv_key))


'''
In ECDSA, each signature has its own ephemeral key k. If k is generated properly, then no amount 
of signatures will help you recover the private key. "Proper" generation here means either random 
uniform selection in the proper range, or an appropriate derandomization process such as the one 
described in RFC 6979.

If the very same k value is used in two signatures, on two distinct messages, but with the same 
private key x, then the private key is revealed. This is the deadly mistake of Sony back in early 
2011 (and the initial motivation for RFC 6979, btw). Indeed, if the two messages are m1 and m2, 
and both values use the same k values, then the two signatures are (r,s1) and (r,s2):

s1s2==(h(m1)+xr)/k(h(m2)+xr)/k

The ephemeral key k, and the private key x, can then be computed as:

kx==h(m1)−h(m2)s1−s2ks1−h(m1)r

If the values of k are not reused, but are generated with some bias (i.e. not all values 
in the [1,q−1] range are selected with the same probability), then the private key x can still 
be recovered from a set of signatures. If for instance q has size 256 bits, but values of k 
are always lower than 253(i.e. the top three bits are always zero), then a few hundreds of 
signatures suffice.

If the values of k are generated with a strong, cryptographically secure source, and with no bias, 
then there is no known attack against ECDSA that would recover the private key x, even if many 
signatures are known. The first reuse of k out of pure back luck is expected to happen after an 
average of 2n/2 signatures for an n-bit curve, i.e. never in practice if you use a decent curve.
'''
