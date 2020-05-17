import base64
import re
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

from bson import json_util


def getDecryptor(key):
    decryptor = PKCS1_OAEP.new(key)
    return decryptor


def getEncryptor(key):
    encryptor = PKCS1_OAEP.new(key)
    return encryptor


def getRSAKeys():
    keyPair = RSA.generate(3072)
    pubKey = keyPair.publickey()
    return pubKey, keyPair


def exportKey(key):
    keyPEM = key.exportKey()
    return keyPEM


def measurePasswordStrength(password):
    strength = 5
    if (len(password) < 7):
        strength -= 5

    if not re.search("[a-z]", password):
        strength -= 1

    if not re.search("[A-Z]", password):
        strength -= 1

    if not re.search("[0-9]", password):
        strength -= 1

    if not re.search("[!#$%&()*+,-./<=>?@\[\]^_{|}~]", password):
        strength -= 1

    if strength < 0:
        strength = 0

    return strength


def getencryptedLogin(pubKey):
    server_encryptor = getEncryptor(pubKey)
    js = {
        'login': 'petok8',
        'password': '4CZ<9_s_z]FeMn'
    }
    key = 'td6d876dtdtd4d'
    js = server_encryptor.encrypt(str.encode(json_util.dumps(js), 'utf-8'))
    print(base64.b64encode(js))
    return base64.b64encode(js)


if __name__ == '__main__':
    pubKey, keyPair = getRSAKeys()

    print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
    pubKeyPEM = pubKey.exportKey()
    print(pubKeyPEM.decode('ascii'))
    #pk = RSA.importKey(pubKeyPEM)
    #print(f"Public key:  (n={hex(pk.n)}, e={hex(pk.e)})")

    print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
    privKeyPEM = keyPair.exportKey()
    print(privKeyPEM.decode('ascii'))
    getencryptedLogin(pubKey)
