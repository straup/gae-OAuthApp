from google.appengine.ext import db

class dbOAuthUser (db.Model) :

  # user_token == access_token but I
  # just find the former easier to remember
  
  password = db.StringProperty()
  user_token = db.StringProperty()
  user_secret = db.StringProperty()  
  perms = db.IntegerProperty()
  created = db.DateTimeProperty(auto_now_add=True)  

# include block stuff here ?
