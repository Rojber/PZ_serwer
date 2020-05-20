import base64
import json
import re
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES
import binascii
import secrets
from bson import json_util


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


def getencryptedLogin(pubKey):
    server_encryptor = getEncryptor(pubKey)
    js = {
        'login': 'vapif',
        'password': '+_g8h=AyYgtmU@2Q'
    }
    js = server_encryptor.encrypt(str.encode(json_util.dumps(js), 'utf-8'))
    print(base64.b64encode(js))
    return base64.b64encode(js)


def encryptAES(text, RSAencryptor):
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


def decryptAES(js, RSAdecryptor):
    #b64 = json.loads(js)
    b64 = js
    json_k = ['nonce', 'encryptedKey', 'cipherText', 'tag']
    jv = {k: base64.b64decode(b64[k]) for k in json_k}
    cipher = AES.new(RSAdecryptor.decrypt(jv['encryptedKey']), AES.MODE_EAX, nonce=jv['nonce'])
    plaintext = cipher.decrypt_and_verify(jv['cipherText'], jv['tag'])
    print('Decrypted text: ' + plaintext.decode('utf-8'))

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
