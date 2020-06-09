from datetime import datetime

def checkToken(token, db):
    userID = None
    outcome = 0
    session = db.sessions.find_one(
        {
            'token': token
        }
    )
    if session is None:
        outcome = 1
        return outcome, None, None
    time_delta = (datetime.utcnow() - session['last_used'])
    total_seconds = time_delta.total_seconds()
    if (total_seconds / 60) < 240:
        userID = session['_id']
        db.sessions.find_one_and_update(
            {
                'token': token
            },
            {
                '$set':
                    {
                        'last_used': datetime.utcnow()
                    }
            }
        )
        return outcome, userID, session['public_key_PEM']
    else:
        db.sessions.remove(
            {
                'token': token
            }, True
        )
        outcome = 1
        return outcome, None, None
