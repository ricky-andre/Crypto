from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1_modules import pem, rfc2459
from hashlib import sha1, sha256
import pyasn1_modules.rfc5280
import pyasn1_modules.rfc2437
import pyasn1_modules.rfc2315
import pyasn1.type.univ
import re
import os

"""
Usually X.509 certificates are written in base64 format, where ASN is 
a standard and generic way to represent information. It's not simple as
other systems (YANG is bad too, but anyway simpler), so it's not widespread
so much. A very good and detailed explanation is the following one:

https://github.com/ajanicij/x509-tutorial/blob/master/x509-analysis.md
"""

DEBUG = True

"""
ChatGPT gave me a wrong answer about padding with pkcs1.5, or let's say incomplete.
Which is equivalent to wrong when you work with cryptography, there is no 'almost right'.

https://medium.com/@bn121rajesh/rsa-sign-and-verify-using-openssl-behind-the-scene-bf3cac0aade2

0x00 || 0x01 || (0xFF * padding) || 0x00 || digestInfo || HASH_OUTPUT

Example output:
0001ffffffffffffffffffffffffffffffffffffffffffffffffffff003021300906052b0e03021a050004148c723a0fa70b111017b4a6f06afe1c0dbcec14e3

In this case the 'DigestInfo' is the following sequence of bytes (hex representation):
3021300906052b0e03021a05000414
SHA-1 output (160 bits, 40 hex characters):
8c723a0fa70b111017b4a6f06afe1c0dbcec14e3

How do you know which cryptographic algorithm has been used, and which padding has been used ? It is of course 
something VERY important. The snmp-like object ID that represents the signature algorithm, also states which padding
algorithm is used, so there can be no doubts about it.

https://cryptography.io/en/latest/x509/reference/

Just a couple of examples:
RSAES_PKCS1_v1_5
Corresponds to the dotted string "1.2.840.113549.1.1.1". This is a RSAPublicKey public key with PKCS1v15 padding.
RSASSA_PSS
Corresponds to the dotted string "1.2.840.113549.1.1.10". This is a RSAPublicKey public key with PSS padding (not covered in this script).
"""

def load_der_certificate(path):
    with open(path, "rb") as f:
        data = f.read()
    if data.startswith(b"-----BEGIN"):
        with open(path, "r") as f:
            # the two approaches are slightly different, it looks like in the first case we get a hash
            # that can be accessed more easily. In the second case we access objects with a function.
            return decode(pyasn1_modules.pem.readPemFromFile(f), asn1Spec=rfc2459.Certificate())[0]
            #return decode(pyasn1_modules.pem.readPemFromFile(f), pyasn1_modules.rfc5280.Certificate())

# beware that modulus is almost always 65537 because it's easy to calculate it. You multiply:
# x*x --> x^2, you multiply the result again by itself ...
# after 16 steps only you get , you're almost there, just multiply the result the last time for x
def public_key_from_certificate (cert):
    tbs = cert["tbsCertificate"]
    spki = tbs["subjectPublicKeyInfo"]
    assert (spki["algorithm"]["algorithm"] == pyasn1_modules.rfc2437.rsaEncryption)
    decode(spki["algorithm"]["parameters"], pyasn1.type.univ.Null())
    rsa_public_key, _ = decode(spki["subjectPublicKey"].asOctets(), pyasn1_modules.rfc2437.RSAPublicKey())
    return (int(rsa_public_key["modulus"]), int(rsa_public_key["publicExponent"]))


def verify_signature (cert, ca_cert):
    # Get the certificate's signature, the signature algorithm is very important and should be retrieved
    # on the certificate to be verified, NOT on the CA certificate.
    signature = cert["signatureValue"]
    if (DEBUG):
        print('Signature Length Bits: '+str(len(signature)))
    # Get the TBSCertificate (or the 'to be signed' certificate part)
    tbs_cert = encode(cert["tbsCertificate"])
    # Resulting Hash is NOT padded here, but the signature is calculated on the padded HASH.
    # We will keep this in mind for the check we do later
    sign_algo = (str)(cert["signatureAlgorithm"]["algorithm"])

    # the calculated signature, elevated to 'exp' power with modulus 'mod,
    # produces as it should the PADDED version of the Hash. For this reason,
    # the output is UN-padded to compare it to the above sha1 value of the certificate.
    ca_mod, ca_exp = public_key_from_certificate (ca_cert)
    signed_int = pow(int(signature), ca_exp, ca_mod)
    signed_bytes = signed_int.to_bytes(len(signature) // 8, "big")
    if (DEBUG):
        print('\nN mod number value:')
        print(str(int(ca_mod)))
        print('\nSIGNATURE INTEGER:')
        print(str(int(signature)))
        print('\nDECRYPTED SIGNATURE INTEGER:')
        print(signed_int)
        print('\nDECRYPTED SIGNATURE BYTES')
        print(signed_bytes.hex())
    
    # sha1, rsa1 with pkcs 1.5 padding
    if (sign_algo == "1.2.840.113549.1.1.5"):
        print("\nSignature algorithm: SHA1 with pkcs1.5 padding, RSA")
        hash_bytes = sha1(tbs_cert).digest()
        if (DEBUG):
            print('\nTarget unpadded result should be:')
            print(hash_bytes.hex())
        if not re.search("^0001[f]+003021300906052b0e03021a05000414", str(signed_bytes.hex())):
            return False
        else:
            # check the last 160bits of the signature, if they are the same it's ok
            return hash_bytes == signed_bytes[-20:]
    # sha256, rsa1 with pkcs 1.5 padding
    elif (sign_algo == "1.2.840.113549.1.1.11"):
        print("\nSignature algorithm: SHA256 with pkcs1.5 padding, RSA")
        hash_bytes = sha256(tbs_cert).digest()
        if (DEBUG):
            print('\nTarget unpadded result should be:')
            print(hash_bytes.hex())
        if not re.search("^0001[f]+003031300d060960864801650304020105000420", str(signed_bytes.hex())):
            return False
        else:
            # check the last 256bits of the signature, if they are the same it's ok
            return hash_bytes == signed_bytes[-32:]
    return False

# Paths to the certificate and CA certificate in DER format
cert_path = "path_to_certificate.cer"
ca_cert_path = "path_to_CA_certificate.cer"

# certificates here are just loaded, not yet decoded
cert = load_der_certificate(cert_path)
ca_cert = load_der_certificate(ca_cert_path)

if verify_signature(cert, ca_cert):
    cert_name = os.path.basename(cert_path).split('/')[-1]
    ca_cert_name = os.path.basename(ca_cert_path).split('/')[-1]
    if (cert_path == ca_cert_path):
        print('The certificate has been correctly SELF-signed by the CA "'+cert_name+'"')
    else:
        print("The certificate has been correctly signed by the CA.")
else:
    if (cert_path == ca_cert_path):
        print('The certificate "'+cert_name+'" has NOT been correctly self-signed.')
    else:
        print("The certificate signature is invalid or has not been signed by the CA.")

