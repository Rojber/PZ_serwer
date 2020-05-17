from bson.binary import STANDARD, UUID, Binary
from pymongo import MongoClient
from bson import CodecOptions
from pymongo.encryption_options import AutoEncryptionOpts
from pymongo.encryption import ClientEncryption
import base64


CONNECTION_STRING = "mongodb+srv://passwordserver:pogchamp@passwordmanager-jxmmz.mongodb.net/test?retryWrites=true&w=majority"


def read_master_key(path="master-key.txt"):
    with open(path, "rb") as f:
        return f.read(96)


class CsfleHelper:
    """This is a helper class that aids in csfle implementation."""

    def __init__(self,
                 kms_providers=None,
                 key_db="encryption",
                 key_coll="__keyVault",
                 key_alt_name=None,
                 schema=None,
                 connection_string=CONNECTION_STRING,
                 # setting this to True requires manually running mongocryptd
                 mongocryptd_bypass_spawn=False,
                 mongocryptd_spawn_path="mongocryptd"):
        """If mongocryptd
        is not installed to in your search path, ensure you override
        mongocryptd_spawn_path
        """
        super().__init__()
        if kms_providers is None:
            raise ValueError("kms_provider is required")
        self.kms_providers = kms_providers
        self.key_alt_name = key_alt_name
        self.key_db = key_db
        self.key_coll = key_coll
        self.key_vault_namespace = f"{self.key_db}.{self.key_coll}"
        self.schema = schema
        self.client_encryption = None
        self.connection_string = connection_string
        self.mongocryptd_bypass_spawn = mongocryptd_bypass_spawn
        self.mongocryptd_spawn_path = mongocryptd_spawn_path

    def ensure_unique_index_on_key_vault(self, key_vault):

        # clients are required to create a unique partial index on keyAltNames
        key_vault.create_index("keyAltNames",
                               unique=True,
                               partialFilterExpression={
                                   "keyAltNames": {
                                       "$exists": True
                                   }
                               })

    def find_or_create_data_key(self):

        key_vault_client = MongoClient(self.connection_string)

        key_vault = key_vault_client[self.key_db][self.key_coll]

        self.ensure_unique_index_on_key_vault(key_vault)

        data_key = key_vault.find_one(
            {"keyAltNames": self.key_alt_name}
        )

        self.client_encryption = ClientEncryption(self.kms_providers,
                                  self.key_vault_namespace,
                                  key_vault_client,
                                  CodecOptions(uuid_representation=STANDARD)
                                  )

        if data_key is None:
                data_key = self.client_encryption.create_data_key(
                    "local", key_alt_names=[self.key_alt_name])
                uuid_data_key_id = UUID(bytes=data_key)

        else:
            uuid_data_key_id = data_key["_id"]

        base_64_data_key_id = (base64
                               .b64encode(uuid_data_key_id.bytes)
                               .decode("utf-8"))

        return uuid_data_key_id, base_64_data_key_id

    def get_regular_client(self):
        return MongoClient(self.connection_string)

    def get_csfle_enabled_client(self, schema):
        return MongoClient(
            self.connection_string,
            auto_encryption_opts=AutoEncryptionOpts(
                self.kms_providers,
                self.key_vault_namespace,
                mongocryptd_bypass_spawn=self.mongocryptd_bypass_spawn,
                mongocryptd_spawn_path=self.mongocryptd_spawn_path,
                bypass_auto_encryption=True,
                schema_map=schema)
        )

    def create_json_schema(self, data_key):
        return {
        'bsonType': 'object',
        'encryptMetadata': {
            'keyId': [Binary(base64.b64decode(data_key), 4)]
        },
        'properties': {
            'email': {
                'encrypt': {
                    'bsonType': "string",
                    'algorithm': "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
                }
            },
            'password': {
                'encrypt': {
                    'bsonType': "string",
                    'algorithm': "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
                }
            },
            'login': {
                'encrypt': {
                    'bsonType': "string",
                    'algorithm': "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
                }
            },
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









"""
CONNECTION_STRING = "mongodb+srv://passwordserver:pogchamp@passwordmanager-jxmmz.mongodb.net/test?retryWrites=true&w=majority"
key_vault_namespace = "encryption.__keyVault"
key_vault_db = "encryption"
key_vault_coll = "__keyVault"
mongoClient = MongoClient(CONNECTION_STRING,
                          connect=False)
path = "master-key.txt"

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

data_key_id = b'n0IapDYvToCnIWseeesa/Q=='

key_vault = mongoClient[key_vault_db][key_vault_coll]

# Pass in the data_key_id created in previous section
key = key_vault.find_one({"_id": data_key_id})
pprint(key)


def json_schema_creator(key_id):
    return {
        'bsonType': 'object',
        'encryptMetadata': {
            'keyId': key_id
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
