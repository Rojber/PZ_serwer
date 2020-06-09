import base64
import pprint
import secrets
import string
from datetime import datetime
import flask
from bson import json_util, ObjectId, Binary
from flask import request
import auxiliaryFuncs
import tokenization
import mongoCli
import populate_database

app = flask.Flask(__name__)
app.config["DEBUG"] = True

#---TWORZENIE KLIENTA MONGODB Z CLIENT SIDE FIELD LEVEL ENCRYPTION
local_master_key = mongoCli.read_master_key()
kms_providers = {
    "local": {
        "key": local_master_key,
    },
}

csfle_helper = mongoCli.CsfleHelper(kms_providers=kms_providers, key_alt_name="main_key")
data_key_id, base64_data_key = csfle_helper.find_or_create_data_key()
data_key_id = Binary(base64.b64decode(base64_data_key), 4)
schema = csfle_helper.create_json_schema(data_key=base64_data_key)
mongoClient = csfle_helper.get_csfle_enabled_client(schema)
db = mongoClient.passwordManager
client_encryption = csfle_helper.client_encryption

#---GENERACJA KLUCZY RSA SERWERA I DEKRYPTORA
public_server_key, private_server_key = auxiliaryFuncs.getRSAKeys()
server_decryptor = auxiliaryFuncs.getDecryptor(private_server_key)
server_encryptor = auxiliaryFuncs.getEncryptor(public_server_key)
export_public_server_key = auxiliaryFuncs.exportKey(public_server_key)
#temp = auxiliaryFuncs.getencryptedLogin(public_server_key)


@app.route('/api/LoginData/<loginID>', methods=['GET', 'PUT', 'DELETE'])
def manageLoginData(loginID):
    try:
        outcome, userID, userKeyPEM = tokenization.checkToken(request.headers['token'], db)
        if outcome == 1:
            return json_util.dumps({'response': 'WRONG TOKEN'}), 401
        if outcome == 2:
            return json_util.dumps({'response': 'SESSION EXPIRED'}), 401

        if request.method == 'GET':
            response = db.accounts.find_one(
                {
                    '_id': ObjectId(userID),
                },
                {
                    'logindata': 1
                }
            )
            for tup in response['logindata']:
                if tup['_id'] == ObjectId(loginID):
                    response = tup
                    break
            return json_util.dumps(auxiliaryFuncs.encryptAES(response, userKeyPEM)), 200

        if request.method == 'PUT':
            js = request.json
            js['passwordStrength'] = auxiliaryFuncs.measurePasswordStrength(js['password'])
            logindat = {
                "_id": ObjectId(loginID),
                'site': js['site'],
                'login': client_encryption.encrypt(js['login'], "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
                'password': client_encryption.encrypt(js['password'], "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
                'passwordStrength': js['passwordStrength'],
                'note': js['note']
            }
            db.accounts.find_one_and_update(
                {
                    '_id': ObjectId(userID), 'logindata._id': ObjectId(loginID)
                },
                {
                    '$set':
                        {
                            "logindata.$": logindat
                        }
                }
            )
            return json_util.dumps(auxiliaryFuncs.encryptAES({'response': 'OK'}, userKeyPEM)), 201

        if request.method == 'DELETE':
            db.accounts.find_one_and_update(
                {
                    '_id': ObjectId(userID)
                },
                {
                    '$pull':
                        {
                            'logindata':
                                {
                                    '_id': ObjectId(loginID)
                                }
                        }
                }
            )
            return json_util.dumps(auxiliaryFuncs.encryptAES({'response': 'OK'}, userKeyPEM)), 200
    except:
        return json_util.dumps({'response': 'INTERNAL SERVER ERROR'}), 500


@app.route('/api/LoginData', methods=['POST'])
def postLoginData():
    try:
        outcome, userID, userKeyPEM = tokenization.checkToken(request.headers['token'], db)
        if outcome == 1:
            return json_util.dumps({'response': 'WRONG TOKEN'}), 401
        if outcome == 2:
            return json_util.dumps({'response': 'SESSION EXPIRED'}), 401

        js = request.json
        if 'passwordStrength' not in js:
            js['passwordStrength'] = auxiliaryFuncs.measurePasswordStrength(js['password'])
        logindat = {
            "_id": ObjectId(),
            'site': js['site'],
            'login': client_encryption.encrypt(js['login'], "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
            'password': client_encryption.encrypt(js['password'], "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
            'passwordStrength': js['passwordStrength'],
            'note': js['note']
        }
        db.accounts.find_one_and_update(
            {'_id': ObjectId(userID)},
            {'$push':
                {
                    'logindata': logindat
                }
            }
        )
        return json_util.dumps(auxiliaryFuncs.encryptAES({'response': 'OK'}, userKeyPEM)), 201
    except:
        return json_util.dumps({'response': 'INTERNAL SERVER ERROR'}), 500


@app.route('/api/AllSites', methods=['GET'])
def getAllSites():
    try:
        outcome, userID, userKeyPEM = tokenization.checkToken(request.headers['token'], db)
        if outcome == 1:
            return json_util.dumps({'response': 'WRONG TOKEN'}), 401
        if outcome == 2:
            return json_util.dumps({'response': 'SESSION EXPIRED'}), 401
        response = db.accounts.find_one(
            {
                '_id': ObjectId(userID)
            },
            {
                'logindata.password': 0,
                'login': 0,
                'password': 0,
                'email': 0
            }
        )
        return json_util.dumps(auxiliaryFuncs.encryptAES(response['logindata'], userKeyPEM)), 200
    except:
        return json_util.dumps({'response': 'INTERNAL SERVER ERROR'}), 500


@app.route('/api/Backup', methods=['GET'])
def getBackup():
    try:
        outcome, userID, userKeyPEM = tokenization.checkToken(request.headers['token'], db)
        if outcome == 1:
            return json_util.dumps({'response': 'WRONG TOKEN'}), 401
        if outcome == 2:
            return json_util.dumps({'response': 'SESSION EXPIRED'}), 401
        response = db.accounts.find_one(
            {
                '_id': ObjectId(userID)
            },
            {
                'logindata': 1
            }
        )
        return json_util.dumps(auxiliaryFuncs.encryptAES(response['logindata'], userKeyPEM)), 200
    except:
        return json_util.dumps({'response': 'INTERNAL SERVER ERROR'}), 500


@app.route('/api/User', methods=['GET', 'PUT', 'DELETE'])
def manageAccount():
    try:
        outcome, userID, userKeyPEM = tokenization.checkToken(request.headers['token'], db)
        if outcome == 1:
            return json_util.dumps({'response': 'WRONG TOKEN'}), 401
        if outcome == 2:
            return json_util.dumps({'response': 'SESSION EXPIRED'}), 401

        if request.method == 'GET':
            response = db.accounts.find_one(
                {
                    '_id': ObjectId(userID)
                },
                {
                    'login': 1,
                    'email': 1
                }
            )
            return json_util.dumps(auxiliaryFuncs.encryptAES(response, userKeyPEM)), 200
        if request.method == 'PUT':
            js = request.json
            js = auxiliaryFuncs.decryptAES(js, server_decryptor)
            logindat = db.accounts.find_one_and_update(
                {
                    '_id': ObjectId(userID)
                },
                {
                    '$set':
                        {
                            'email': client_encryption.encrypt(js['email'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                                                               data_key_id),
                            'login': client_encryption.encrypt(js['login'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                                                               data_key_id),
                            'password': client_encryption.encrypt(js['password'], "AEAD_AES_256_CBC_HMAC_SHA_512-Random",
                                                                  data_key_id)
                        }
                }
            )
            return json_util.dumps(auxiliaryFuncs.encryptAES({'response': 'OK'}, userKeyPEM)), 201
        if request.method == 'DELETE':
            db.accounts.remove(
                {
                    '_id': ObjectId(userID)
                }, True
            )
            return json_util.dumps(auxiliaryFuncs.encryptAES({'response': 'OK'}, userKeyPEM)), 200
    except:
        return json_util.dumps({'response': 'INTERNAL SERVER ERROR'}), 500


@app.route('/api/SignUp', methods=['POST'])
def signUp():
    try:
        #TYLKO RSA
        js = base64.b64decode(request.get_data())
        js = server_decryptor.decrypt(js)
        js = json_util.loads(js.decode('utf-8'))
        pprint.pprint(js)

        check = db.accounts.find_one(
            {
                'login': client_encryption.encrypt(js['login'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", data_key_id)
            }
        )
        if check is not None:
            return json_util.dumps({'response': 'LOGIN ALREADY USED'}), 400

        check = db.accounts.find_one(
            {
                'email': client_encryption.encrypt(js['email'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", data_key_id)
            }
        )
        if check is not None:
            return json_util.dumps({'response': 'EMAIL ALREADY USED'}), 400

        account = {
            'email': client_encryption.encrypt(js['email'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", data_key_id),
            'login': client_encryption.encrypt(js['login'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", data_key_id),
            'password': client_encryption.encrypt(js['password'], "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
            'logindata': []
        }
        result = db.accounts.insert_one(account)
        return json_util.dumps({'response': 'OK'}), 201
    except:
        return json_util.dumps({'response': 'INTERNAL SERVER ERROR'}), 500


@app.route('/api/SignIn', methods=['POST'])
def singIn():
    try:
        result = None
        #TYLKO RSA
        json = request.json
        js = base64.b64decode(json['data'].encode('utf-8'))
        js = server_decryptor.decrypt(js)
        js = json_util.loads(js.decode('utf-8'))

        response = db.accounts.find_one(
            {
                'login': client_encryption.encrypt(js['login'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", data_key_id),
            },
            {
                'password': 1,
                '_id': 1
            }
        )
        if response['password'] == js['password']:
            session = db.sessions.find_one(
                {
                    '_id': response['_id']
                }
            )
            token = auxiliaryFuncs.getToken()
            if session is None:
                session = {
                    '_id': response['_id'],
                    'token': token,
                    'last_used': datetime.utcnow(),
                    'public_key_PEM': json['public_key_PEM']
                }
                db.sessions.insert_one(session)
                result = token
            else:
                db.sessions.find_one_and_update(
                    {
                        'token': session['token']
                    },
                    {
                        '$set':
                            {
                                'token': token,
                                'last_used': datetime.utcnow(),
                                'public_key_PEM': json['public_key_PEM']
                            }
                    }
                )
                result = token
        else:
            return json_util.dumps({'response': 'NOT LOGGED IN'}), 401

        resp = {
            'response': result
        }
        return json_util.dumps(auxiliaryFuncs.encryptAES(resp, json['public_key_PEM'])), 200
    except:
        return json_util.dumps({'response': 'INTERNAL SERVER ERROR'}), 500


@app.route('/api/PasswordStrength', methods=['POST'])
def getPasswordStrength():
    try:
        #TYLKO RSA
        js = base64.b64decode(request.get_data())
        js = server_decryptor.decrypt(js)
        js = json_util.loads(js.decode('utf-8'))
        pprint.pprint(js)

        password = js['password']
        resp = {
            'passwordStrength': auxiliaryFuncs.measurePasswordStrength(password)
        }
        return json_util.dumps(resp), 200
    except:
        return json_util.dumps({'response': 'INTERNAL SERVER ERROR'}), 500


@app.route('/api/StrongPassword/<PasswordLen>', methods=['GET'])
def getStrongPassword(PasswordLen):
    try:
        outcome, _, userKeyPEM = tokenization.checkToken(request.headers['token'], db)
        if outcome == 1:
            return json_util.dumps({'response': 'WRONG TOKEN'}), 401
        if outcome == 2:
            return json_util.dumps({'response': 'SESSION EXPIRED'}), 401

        chars = string.ascii_letters + string.digits + "!#$%&()*+,-./<=>?@[]^_{|}~"
        passw = ''.join(secrets.choice(chars) for i in range(int(PasswordLen)))
        return json_util.dumps(auxiliaryFuncs.encryptAES({'response': str(passw)}, userKeyPEM)), 200
    except:
        return json_util.dumps({'response': 'INTERNAL SERVER ERROR'}), 500


@app.route('/api/PasswordStrength/Hibp', methods=['POST'])
def passwordCheckHIBP():
    try:
        outcome, _, userKeyPEM = tokenization.checkToken(request.headers['token'], db)
        if outcome == 1:
            return json_util.dumps({'response': 'WRONG TOKEN'}), 401
        if outcome == 2:
            return json_util.dumps({'response': 'SESSION EXPIRED'}), 401

        js = request.json
        js = auxiliaryFuncs.decryptAES(js, server_decryptor)

        password = js['password']
        if auxiliaryFuncs.hibpIsPwned(password) is True:
            return json_util.dumps(auxiliaryFuncs.encryptAES({'response': 'PASSWORD LEAKED'}, userKeyPEM)), 200
        else:
            return json_util.dumps(auxiliaryFuncs.encryptAES({'response': 'OK'}, userKeyPEM)), 200
    except:
        return json_util.dumps({'response': 'INTERNAL SERVER ERROR'}), 500


@app.route('/api/GetPublicKey', methods=['GET'])
def getKey():
    return export_public_server_key, 200


##DEBUG
@app.route('/api/Populate', methods=['GET'])
def pop():
    populate_database.populate(db, client_encryption, data_key_id)
    return 'Database Populated with 20 accounts!', 200


##DEBUG
@app.route('/api/AllData', methods=['GET'])
def allData():
    response = db.accounts.find()
    return json_util.dumps(response), 200


##DEBUG
@app.route('/api/DropDb', methods=['GET'])
def dropDb():
    db.accounts.drop()
    return 'Database cleared!', 200


if __name__ == '__main__':
    app.run()
