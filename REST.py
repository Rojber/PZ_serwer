import os
import flask
from flask import request
from pymongo import MongoClient
from pprint import pprint
from bson import json_util, ObjectId
from boto.s3.connection import S3Connection, Bucket, Key
import json
import populate_database

# pogchamp
print("Podaj hasło do bazy danych: ")
s3 = S3Connection(os.environ['DATABASE_PASSWORD'])
b = Bucket(s3, 'DATABASE_PASSWORD')
k = Key(b)
password = s3.__getattribute__('DATABASE_PASSWORD')
mongoClient = MongoClient("mongodb+srv://passwordserver:" + password + "@passwordmanager-jxmmz.mongodb.net/test?retryWrites=true&w=majority",
    connect=False)
##mongoClient = None
db = mongoClient.passwordManager
app = flask.Flask(__name__)
app.config["DEBUG"] = True


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
        return 'OK', 200
    if request.method == 'DELETE':
        return 'OK', 200


@app.route('/api/user/<userID>/LoginData', methods=['POST'])
def postLoginData(userID):
    return 'OK', 200


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


@app.route('/api/PasswordStrength', methods=['GET'])
def getPasswordStrength():
    ##TODO sprawdzanie siły hasła (haveibeenpwnd tez?)
    return 'OK', 200


@app.route('/api/StrongPassword', methods=['GET'])
def getStrongPassword():
    ##TODO generowanie silnego hasła
    return 'OK', 200


@app.route('/api/Account', methods=['POST', 'PUT', 'DELETE'])
def manageAccount():
    return 'OK', 200


@app.route('/api/SignIn', methods=['POST'])
def singIn():
    return 'OK', 200


@app.route('/api/Note', methods=['PUT'])
def updateNote():
    return 'OK', 200


##DEBUG
@app.route('/api/Populate', methods=['GET'])
def pop():
    populate_database.populate(db)
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
