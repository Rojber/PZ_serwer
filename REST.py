import string
import flask
import re
from flask import request
from bson import json_util, ObjectId, Binary
import base64
import secrets
import populate_database, mongoCli

app = flask.Flask(__name__)
app.config["DEBUG"] = True

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

"""
CONNECTION_STRING = "mongodb+srv://passwordserver:pogchamp@passwordmanager-jxmmz.mongodb.net/test?retryWrites=true&w=majority"
key_vault_namespace = "encryption.__keyVault"
key_vault_db = "encryption"
key_vault_coll = "__keyVault"
mongoClient = MongoClient(CONNECTION_STRING,
                          connect=False)
path = "master-key.txt"



file_bytes = os.urandom(96)
with open(path, "wb") as f:
    f.write(file_bytes)


with open(path, "rb") as f:
    local_master_key = f.read()

kms_providers = {
    "local": {
        "key": local_master_key
    },
}

client_encryption = ClientEncryption(
    kms_providers,  # pass in the kms_providers variable from the previous step
    key_vault_namespace,
    mongoClient,
    CodecOptions(uuid_representation=STANDARD)
)

def create_data_encryption_key():
    data_key_id = client_encryption.create_data_key("local")
    uuid_data_key_id = UUID(bytes=data_key_id)
    base_64_data_key_id = base64.b64encode(data_key_id)
    print("DataKeyId [UUID]: ", str(uuid_data_key_id))
    print("DataKeyId [base64]: ", base_64_data_key_id)
    print(data_key_id)
    return data_key_id

data_key_id = base64.b64encode(b'\xd3j\xab\xb4[\x9fBS\x85\x9a\xd1~\xa3[QY')

key_vault = mongoClient[key_vault_db][key_vault_coll]

# Pass in the data_key_id created in previous section
key = key_vault.find_one({"_id": [Binary(base64.b64decode(data_key_id), OLD_UUID_SUBTYPE)]})
pprint(key)


def json_schema_creator(key_id):
    return {
        'bsonType': 'object',
        'encryptMetadata': {
            'keyId': [Binary(base64.b64decode(data_key_id), OLD_UUID_SUBTYPE)]
        },
        'properties': {
            'logindata': {
                'bsonType': "object",
                'properties': {
                    'password': {
                        'encrypt': {
                            'bsonType': "string",
                            'algorithm': "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
                        }
                    },
                    'login': {
                        'encrypt': {
                            'bsonType': "string",
                            'algorithm': "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
                        }
                    }
                }
            }
        }
    }


json_schema = json_schema_creator(data_key_id)
accounts_schema = {
    "passwordManager.accounts": json_schema
}

fle_opts = AutoEncryptionOpts(
    kms_providers,
    key_vault_namespace,
    schema_map=accounts_schema,
    bypass_auto_encryption=True,
)
mongoClient = MongoClient(CONNECTION_STRING, auto_encryption_opts=fle_opts)
db = mongoClient.passwordManager
"""


@app.route('/api/user/<userID>/LoginData/<loginID>', methods=['GET', 'PUT', 'DELETE'])
def manageLoginData(userID, loginID):
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
        return json_util.dumps(logindat), 200
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
        return 'OK', 200


@app.route('/api/user/<userID>/LoginData', methods=['POST'])
def postLoginData(userID):
    js = request.json
    if 'passwordStrength' not in js:
        # TODO ZMIEN NA FUNKCJE LICZACA SILE HASŁA
        js['passwordStrength'] = 3
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
    return json_util.dumps(logindat), 200


@app.route('/api/user/<userID>/AllSites', methods=['GET'])
def getAllSites(userID):
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
    return json_util.dumps(response['logindata']), 200


@app.route('/api/user/<userID>/Backup', methods=['GET'])
def getBackup(userID):
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

    js['passwordStrength'] = strength

    ##TODO sprawdzanie siły hasła (haveibeenpwnd tez?)
    return json_util.dumps(js), 200


@app.route('/api/StrongPassword/<PasswordLen>', methods=['GET'])
def getStrongPassword(PasswordLen):
    chars = string.ascii_letters + string.digits + "!#$%&()*+,-./<=>?@[]^_{|}~"
    passw = ''.join(secrets.choice(chars) for i in range(int(PasswordLen)))
    return str(passw), 200


@app.route('/api/user/<userID>', methods=['PUT', 'DELETE'])
def manageAccount(userID):
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
        logindat['email'] = client_encryption.encrypt(js['email'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                                                      data_key_id),
        logindat['login'] = client_encryption.encrypt(js['login'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
                                                      data_key_id),
        logindat['password'] = client_encryption.encrypt(js['password'], "AEAD_AES_256_CBC_HMAC_SHA_512-Random",
                                                         data_key_id),
        return json_util.dumps(logindat), 200
    if request.method == 'DELETE':
        db.accounts.remove(
            {
                '_id': ObjectId(userID)
            }, True
        )
        return 'OK', 200


@app.route('/api/SignUp', methods=['POST'])
def signUp():
    js = request.json
    account = {
        'email': client_encryption.encrypt(js['email'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", data_key_id),
        'login': client_encryption.encrypt(js['login'], "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", data_key_id),
        'password': client_encryption.encrypt(js['password'], "AEAD_AES_256_CBC_HMAC_SHA_512-Random", data_key_id),
        'logindata': []
    }
    result = db.accounts.insert_one(account)
    account['_id'] = ObjectId(result.inserted_id)
    return json_util.dumps(account), 200


@app.route('/api/SignIn', methods=['POST'])
def singIn():
    # TODO OGARNIJ LOGOWANIE
    return 'OK', 200


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
