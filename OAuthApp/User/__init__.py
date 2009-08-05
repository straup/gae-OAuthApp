from google.appengine.ext import db
from OAuthApp.Tables import dbOAuthUser

def get_user_by_password (password) :

    users = db.GqlQuery("SELECT * FROM dbOAuthUser WHERE password = :1", password)
    return users.get()

# get by username stuff here?

def create (args) :

    user = dbFlickrUser()
    user.password = args['password']
    user.user_token = args['token']
    user.user_secret = args['secret']    
    user.perms = args['perms']

    user.put()
    return user

def update_credentials (user, creds) :

    user.user_token = creds['token']
    user.user_secret = creds['secret']
    user.perms = creds['perms']
    user.username = creds['username']
    user.put()

