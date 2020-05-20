import string
from datetime import datetime, timedelta
import flask
from flask import request
from bson import json_util, ObjectId, Binary
import base64
import secrets
import populate_database, mongoCli, auxiliaryFuncs


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
temp = auxiliaryFuncs.getencryptedLogin(public_server_key)


@app.route('/api/LoginData/<loginID>', methods=['GET', 'PUT', 'DELETE'])
def manageLoginData(loginID):
    userID = None
    token = request.headers['token']
    session = db.sessions.find_one(
        {
            'token': token
        }
    )
    if session is None:
        return json_util.dumps({'response': 'WRONG TOKEN'}), 200
    time_delta = (datetime.utcnow() - session['last_used'])
    total_seconds = time_delta.total_seconds()
    if (total_seconds / 60) < 240:
        userID = session['_id']
    else:
        db.sessions.remove(
            {
                'token': token
            }, True
        )
        return json_util.dumps({'response': 'SESSION EXPIRED'}), 200

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
        return json_util.dumps(response), 200
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
        return json_util.dumps({'response': 'OK'}), 200
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
        return json_util.dumps({'response': 'OK'}), 200


@app.route('/api/LoginData', methods=['POST'])
def postLoginData():
    userID = None
    token = request.headers['token']
    session = db.sessions.find_one(
        {
            'token': token
        }
    )
    if session is None:
        return json_util.dumps({'response': 'WRONG TOKEN'}), 200
    time_delta = (datetime.utcnow() - session['last_used'])
    total_seconds = time_delta.total_seconds()
    if (total_seconds / 60) < 240:
        userID = session['_id']
    else:
        db.sessions.remove(
            {
                'token': token
            }, True
        )
        return json_util.dumps({'response': 'SESSION EXPIRED'}), 200

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
    return json_util.dumps({'response': 'OK'}), 200


@app.route('/api/AllSites', methods=['GET'])
def getAllSites():
    userID = None
    token = request.headers['token']
    session = db.sessions.find_one(
        {
            'token': token
        }
    )
    if session is None:
        return json_util.dumps({'response': 'WRONG TOKEN'}), 200
    time_delta = (datetime.utcnow() - session['last_used'])
    total_seconds = time_delta.total_seconds()
    if (total_seconds / 60) < 240:
        userID = session['_id']
    else:
        db.sessions.remove(
            {
                'token': token
            }, True
        )
        return json_util.dumps({'response': 'SESSION EXPIRED'}), 200

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
    #js = auxiliaryFuncs.encryptAES(json_util.dumps(response['logindata']), server_encryptor)
    #auxiliaryFuncs.decryptAES(js, server_decryptor)
    return json_util.dumps(response['logindata']), 200


@app.route('/api/Backup', methods=['GET'])
def getBackup():
    userID = None
    token = request.headers['token']
    session = db.sessions.find_one(
        {
            'token': token
        }
    )
    if session is None:
        return json_util.dumps({'response': 'WRONG TOKEN'}), 200
    time_delta = (datetime.utcnow() - session['last_used'])
    total_seconds = time_delta.total_seconds()
    if (total_seconds / 60) < 240:
        userID = session['_id']
    else:
        db.sessions.remove(
            {
                'token': token
            }, True
        )
        return json_util.dumps({'response': 'SESSION EXPIRED'}), 200

    response = db.accounts.find_one(
        {
            '_id': ObjectId(userID)
        },
        {
            'logindata': 1
        }
    )
    return json_util.dumps(response['logindata']), 200


@app.route('/api/PasswordStrength', methods=['POST'])
def getPasswordStrength():
    js = request.json
    password = js['password']
    resp = {
        'passwordStrength': auxiliaryFuncs.measurePasswordStrength(password)
    }
    ##TODO haveibeenpwnd
    return json_util.dumps(resp), 200


@app.route('/api/StrongPassword/<PasswordLen>', methods=['GET'])
def getStrongPassword(PasswordLen):
    chars = string.ascii_letters + string.digits + "!#$%&()*+,-./<=>?@[]^_{|}~"
    passw = ''.join(secrets.choice(chars) for i in range(int(PasswordLen)))
    return json_util.dumps({'response': str(passw)}), 200


@app.route('/api/User', methods=['GET', 'PUT', 'DELETE'])
def manageAccount():
    userID = None
    token = request.headers['token']
    session = db.sessions.find_one(
        {
            'token': token
        }
    )
    if session is None:
        return json_util.dumps({'response': 'WRONG TOKEN'}), 200
    time_delta = (datetime.utcnow() - session['last_used'])
    total_seconds = time_delta.total_seconds()
    if  (total_seconds / 60) < 240:
        userID = session['_id']
    else:
        db.sessions.remove(
            {
                'token': token
            }, True
        )
        return json_util.dumps({'response': 'SESSION EXPIRED'}), 200

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
        return json_util.dumps(response), 200
    if request.method == 'PUT':
        js = request.json
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
        return json_util.dumps({'response': 'OK'}), 200
    if request.method == 'DELETE':
        db.accounts.remove(
            {
                '_id': ObjectId(userID)
            }, True
        )
        return json_util.dumps({'response': 'OK'}), 200


@app.route('/api/SignUp', methods=['POST'])
def signUp():
    js = request.json
    check = db.accounts.find_one(
        {
            'login': client_encryption.encrypt(js['login'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", data_key_id)
        }
    )
    if check is not None:
        return json_util.dumps({'response': 'LOGIN ALREADY USED'}), 200
    check = db.accounts.find_one(
        {
            'email': client_encryption.encrypt(js['email'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", data_key_id)
        }
    )
    if check is not None:
        return json_util.dumps({'response': 'EMAIL ALREADY USED'}), 200

    account = {
        'email': client_encryption.encrypt(js['email'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", data_key_id),
        'login': client_encryption.encrypt(js['login'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", data_key_id),
        'password': client_encryption.encrypt(js['password'], "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
        'logindata': []
    }
    result = db.accounts.insert_one(account)
    print(result.inserted_id)
    account['_id'] = ObjectId(result.inserted_id)
    return json_util.dumps({'response': 'OK'}), 200


@app.route('/api/SignIn', methods=['POST'])
def singIn():
    result = None
    js = base64.b64decode(request.get_data())
    #print(js)
    #print(type(js))
    #print(type(temp))
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
        if session is None:
            token = auxiliaryFuncs.getToken()
            session = {
                '_id': response['_id'],
                'token': token,
                'last_used': datetime.utcnow()
            }

            db.sessions.insert_one(session)
            result = token
        else:
            token = session['token']
            result = token
    else:
        result = 'NOT LOGGED IN'

    resp = {
        'response': result
    }
    return json_util.dumps(resp), 200


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
