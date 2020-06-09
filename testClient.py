import base64
import pprint

import requests
from bson import json_util
import auxiliaryFuncs
import time
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES

def print_request(request):
    print('------------------------------------')
    print('request.url:', request.url)
    print('request.status_code:', request.status_code)
    print('request.headers:', request.headers)
    print('request.text', request.text)
    if request.request.body is not None:
        print('request.request.body:', request.request.body)
    print('request.request.headers:', request.request.headers)
    print('------------------------------------')


def getencryptedLogin(pubKey, jss):
    server_encryptor = auxiliaryFuncs.getEncryptor(RSA.importKey(pubKey))
    temp = server_encryptor.encrypt(json_util.dumps(jss).encode('utf-8'))
    temp = base64.b64encode(temp).decode('utf-8')
    #print(temp)
    jss = temp
    return jss


if __name__ == '__main__':
    RSApublic, RSAprivate = auxiliaryFuncs.getRSAKeys()
    request = requests.get('http://127.0.0.1:5000/api/GetPublicKey')
    print_request(request)
    server_key_PEM = request.text
    time.sleep(0.01)

    js2 = {"login": "vapif", "password": "Tc!D#u6R45vQH4gt"}
    js2 = getencryptedLogin(server_key_PEM, js2)
    js = {"data": js2, "public_key_PEM": RSApublic.exportKey().decode('utf-8')}
    pprint.pprint(js)
    request = requests.post('http://127.0.0.1:5000/api/SignIn', json=js)
    print_request(request)
    js = request.json()
    js = auxiliaryFuncs.decryptAES(js, auxiliaryFuncs.getDecryptor(RSAprivate))
    token = js['response']
    time.sleep(0.01)

    request = requests.get('http://127.0.0.1:5000/api/AllSites', headers={"token": token})
    print_request(request)
    js = request.json()
    js = auxiliaryFuncs.decryptAES(js, auxiliaryFuncs.getDecryptor(RSAprivate))
    pprint.pprint(js)
    time.sleep(0.01)

    request = requests.get('http://127.0.0.1:5000/api/LoginData/' + str(js[0]['_id']), headers={"token": token})
    print_request(request)
    js = request.json()
    js = auxiliaryFuncs.decryptAES(js, auxiliaryFuncs.getDecryptor(RSAprivate))
    pprint.pprint(js)
    time.sleep(0.01)