import base64
import requests
import re
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES
import secrets
from bson import json_util
import hashlib


def getToken():
    return secrets.token_hex(24)


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


"""
def encryptAES(js, userKeyPEM):
    text = json_util.dumps(js)
    print('\n\n\n\nKEY PEM: ' + str(userKeyPEM))
    RSAencryptor = PKCS1_OAEP.new(RSA.importKey(userKeyPEM))
    AESkey = get_random_bytes(16)
    encryptedAESkey = RSAencryptor.encrypt(AESkey)
    AESencryptor = AES.new(AESkey, AES.MODE_EAX)
    cipherText, tag = AESencryptor.encrypt_and_digest(text.encode("utf-8"))

    result = {
        'nonce': base64.b64encode(AESencryptor.nonce).decode('utf-8'),
        'cipherText': base64.b64encode(cipherText).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8'),
        'encryptedKey': base64.b64encode(encryptedAESkey).decode('utf-8'),
    }
    return result
"""


def encryptAES(js, userKeyPEM):
    text = json_util.dumps(js)
    print('\n\n\n\nKEY PEM: ' + str(userKeyPEM))
    RSAencryptor = PKCS1_OAEP.new(RSA.importKey(userKeyPEM))
    AESkey = get_random_bytes(16)
    nonce = get_random_bytes(16)
    encryptedAESkey = RSAencryptor.encrypt(AESkey)
    AESencryptor = AES.new(AESkey, AES.MODE_GCM, nonce=nonce)
    cipherText, tag = AESencryptor.encrypt_and_digest(text.encode("utf-8"))

    print('noncebytes: ')
    print(nonce)
    print('ciphertextbytes: ')
    print(cipherText)
    print('tagbytes: ')
    print(tag)
    print('encryptedKeybytes: ')
    print(encryptedAESkey)

    result = {
        'nonce': base64.b64encode(AESencryptor.nonce).decode('utf-8'),
        'cipherText': base64.b64encode(cipherText).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8'),
        'encryptedKey': base64.b64encode(encryptedAESkey).decode('utf-8'),
        'aesKey': base64.b64encode(AESkey).decode('utf-8'),
        'userPEM': str(userKeyPEM)
    }
    return result


"""
def decryptAES(js, RSAdecryptor):
    json_k = ['nonce', 'encryptedKey', 'cipherText', 'tag']
    jv = {k: base64.b64decode(js[k]) for k in json_k}
    cipher = AES.new(RSAdecryptor.decrypt(jv['encryptedKey']), AES.MODE_EAX, nonce=jv['nonce'])
    plaintext = cipher.decrypt_and_verify(jv['cipherText'], jv['tag'])
    print('Decrypted text: ' + plaintext.decode('utf-8'))
    return json_util.loads(plaintext.decode('utf-8'))
"""


def decryptAES(js, RSAdecryptor):
    json_k = ['nonce', 'encryptedKey', 'cipherText', 'tag']
    jv = {k: base64.b64decode(js[k]) for k in json_k}
    aesKey = RSAdecryptor.decrypt(jv['encryptedKey'])
    cipher = AES.new(aesKey, AES.MODE_GCM, nonce=jv['nonce'])
    plaintext = cipher.decrypt_and_verify(jv['cipherText'], jv['tag'])
    print('Decrypted text: ' + plaintext.decode('utf-8'))
    return json_util.loads(plaintext.decode('utf-8'))



def hibpIsPwned(password):
    shaPassword = hashlib.sha1(password.encode('utf-8'))
    req = requests.get('https://api.pwnedpasswords.com/range/' + str(shaPassword.hexdigest())[:5].upper())
    print(str(shaPassword.hexdigest())[:5].upper())
    result = req.text.find(str(shaPassword.hexdigest())[5:].upper())
    print(str(shaPassword.hexdigest())[5:].upper())
    if result > 0:
        return True
    else:
        return False


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
