from pymongo import MongoClient
from random import randint
from bson.objectid import ObjectId

"""
mongoClient = MongoClient("mongodb://127.0.0.1:27017")
dbb = mongoClient.test
dbb.reviewe.drop()
dbb.accounts.drop()
"""

def populate(db):
    emails = ['wocolok826@mailboxt.com','bahipa4662@itiomail.com','petok85924@mailmyrss.com', 'vasem29004@itiomail.com', 'vapif21218@ualmail.com']
    logins = ['wocolok','bahipa4','petok8','vase','vapif','tribert']
    passwords = ['g!AWS{=MA,2kk4Sn', ';,*af=<}%@5,N[+g', '?#w4}PU3A^$XqyC%', '4CZ<9_s_z]FeMn', '+_g8h=AyYgtmU@2Q', 'Tc!D#u6R45vQH4gt', 'KcqPUQ@T#w2Uw%+!']
    sites = ['https://www.flightradar24.com/','https://www.gutenberg.org/', 'http://slither.io/', 'https://www.tumblr.com/login_required/ihumans', 'http://www.danielyeow.com/2011/drawing-molecules/', 'http://www.museumofconceptualart.com/accomplished/index.html', 'http://www.muppetlabs.com/~breadbox/txt/al.html']
    passwordsLD = ['UuwBHAOOyck', 'uDH2tMT', 'uinYv9AP7t', 'CUF6lAj', 'L5iW1Bx', 'a1AaX5F74lQZ', 'MQYLa8DuFE', 'XYxjFXdYjBb', '3uawhI', '64LdRp']
    loginsLD = ['ehebborn1', 'ydaughtreyd', 'cmundyk', 'csurr2', 'wmoreno6', 'kchesonc', 'rdegiorgisf', 'jmcpakep', 'lloudwells', 'staitt', 'ymegsona']
    notesLD = ['Fliptune', 'Linkbridge', 'Linkbuzz', 'Janyx', 'Eabox', 'Browseblab', 'Chatterpoint', 'Blogspan', 'WikidoWikido', 'Tazzy', 'Miboo']
    for x in range(1, 20):
        account = {
            'email' : emails[randint(0, (len(emails)-1))],
            'login' : logins[randint(0, (len(logins)-1))],
            'password': passwords[randint(0, (len(passwords) - 1))],
            'logindata' : [
                {
                    "_id": ObjectId(),
                    'site': sites[randint(0, (len(sites) - 1))],
                    'login': loginsLD[randint(0, (len(loginsLD) - 1))],
                    'password': passwordsLD[randint(0, (len(passwordsLD) - 1))],
                    'passwordStrength': randint(1, 5),
                    'note': notesLD[randint(0, (len(notesLD) - 1))]
                },
                {
                    "_id": ObjectId(),
                    'site': sites[randint(0, (len(sites) - 1))],
                    'login': loginsLD[randint(0, (len(loginsLD) - 1))],
                    'password': passwordsLD[randint(0, (len(passwordsLD) - 1))],
                    'passwordStrength': randint(1,5),
                    'note': notesLD[randint(0, (len(notesLD) - 1))]
                }
            ]
        }
        #Step 3: Insert business object directly into MongoDB via isnert_one
        result=db.accounts.insert_one(account)
        #Step 4: Print to the console the ObjectID of the new document
        print('Created {0} of 20 as {1}'.format(x,result.inserted_id))
    #Step 5: Tell us that you are done
    print('Finished creating 20 accounts')

"""
populate(dbb)
for c in dbb['accounts'].find():
    pprint(c)
"""
