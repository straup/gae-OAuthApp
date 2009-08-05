from google.appengine.ext import webapp
from django.utils import simplejson

import OAuthApp.User as User
from OAuthApp.ext import pyDes
from OAuthApp.ext.oauth import oauth

import md5
import os
import binascii
import time
import datetime
import urllib
from urlparse import urlparse
import string
import random
import base64

class OAuthApp (webapp.RequestHandler) :

  # #########################################
  # BOILER-PLATE DELEGATEDAUTH STUFF

  def __init__ (self, service_endpoint, service_apikey, service_apisecret, perms_map) :
   
    webapp.RequestHandler.__init__(self)

    self.service_endpoint = service_endpoint
    self.service_apikey = service_apikey
    self.service_apisecret = service_apisecret

    self.signature_method = 'fixme'
    
    # FIX ME: does this really make sense?
    self.perms_map = perms_map

    self.user = None
    self.min_perms = None    
    self.crypto = None

    self.canhas_crypto()

  # please to put in DelegatedAuthApp
  
  def canhas_crypto (self) :

    # A placeholder for some imaginary better day...
    # This isn't necessarily fast but then it doesn't
    # really need to be so let's just go with the
    # simple thing for now.
    
    self.crypto = 'pydes'
    return True

  # please to put in DelegatedAuthApp

  def check_logged_in (self, min_perms=None) :
    
    cookies = self.request.cookies

    if not cookies.has_key('ffo') :
      return False
    
    whoami = cookies['ffo'].split(":")

    if len(whoami) != 2 :
      return False

    user = User.get_user_by_password(whoami[1])

    if not user :
      return False

    self.user = user

    if str(self.user.key()) != str(whoami[0]) :
      return False

    if min_perms :

      if cookies.has_key('fft') :

        # check that the cookie looks sane
        
        fft = self.generate_fft(self.user)

        if cookies['fft'] != fft :
          return False

        # check that the user token has
        # some minimum permissions
        
        need_perms = self.perms_map[min_perms]
        has_perms = self.user.perms

        if has_perms < need_perms :
          return False

      else :

        if not self.check_token(min_perms) :
          return False
          
    return True

  # please to put in DelegatedAuthApp
  
  def generate_ffo (self, user) :
    
    ffo = "%s:%s" % (user.key(), user.password)
    return ffo

  # please to put in DelegatedAuthApp
  
  def ffo_cookie (self, user) :

    now = datetime.datetime.fromtimestamp(time.time())
    delta = datetime.timedelta(days=30)
    then = now + delta
    expires = then.strftime("%a, %e-%b-%Y %H:%M:%S GMT")
    
    ffo = self.generate_ffo(user)
    ffo_cookie = "ffo=%s; expires=%s" % (ffo, expires)
    return str(ffo_cookie)

  def generate_fft (self, user) :

    # NOTE TO SELF: if there really is a DelegatedAuthApp
    # class that FlickApp inherits, the latter will need
    # to define a custom version of this method...
    
    if user :
      fft = "%s-%s-%s" % (user.user_secret, user.user_token, user.perms)
    else :
      fft = "%s-%s" % (self.service_apisecret, self.request.remote_addr)
      
    hash = md5.new()
    hash.update(fft)

    return hash.hexdigest()

  def fft_cookie (self, user) :
    
    fft = self.generate_fft(user)
    fft_cookie = "fft=%s" % fft
    return str(fft_cookie)
  
  def generate_password (self, length=58) :
    
    return self.generate_secret(length)

  def generate_confirmation_code (self, length) :
    
    code = self.generate_secret(length)
    code = code.replace("/", self.generate_alpha())
    code = code.replace("+", self.generate_alpha())
    code = code.replace("=", self.generate_alpha())       
    return code
  
  def generate_alpha (self) :
    
    if int(time.time()) % 2 :
      return string.lowercase[random.randint(0, len(string.uppercase)-1)]
    
    return string.uppercase[random.randint(0, len(string.lowercase)-1)]    

  def generate_secret (self, length) :

    return binascii.b2a_base64(os.urandom(length)).strip()

  def crumb_secret (self, user) :

    # NOTE TO SELF: see generate_fft inre subclassing
    
    if user : 
      secret = "%s%s" % (user.user_secret, user.password)
    else :
      secret = "%s%s" % (self.service_apisecret, self.request.user_agent)
      
    hash = md5.new()
    hash.update(secret)
    hex = hash.hexdigest()
    
    return hex[:8]

  def generate_crumb (self, user, path, ttl=120) :

    # ttl is measured in minutes

    fft = self.generate_fft(user)
    secret = self.crumb_secret(user)
      
    now = datetime.datetime.fromtimestamp(time.time())
    delta = datetime.timedelta(minutes=ttl)
    then = now + delta
    expires = then.strftime("%s")

    crumb = "%s:%s:%s" % (fft, path, expires)
    
    enc = self.encrypt(crumb, secret)
    return base64.b64encode(enc)

  def validate_crumb(self, user, path, crumb_b64) :
    
    secret = self.crumb_secret(user)    

    crumb_enc = base64.b64decode(crumb_b64)
    crumb_raw = self.decrypt(crumb_enc, secret)

    if not crumb_raw :
      return False

    try :
      (crumb_fft, crumb_path, crumb_expires) = crumb_raw.split(":")
    except Exception, e :
      return False

    if crumb_fft != self.generate_fft(user) :
      return False

    if crumb_path != path :
      return False
    
    if (int(crumb_expires) < int(time.time())) :
      return False

    return True

  def encrypt (self, raw, secret) :

    des = pyDes.des(secret)
    enc = des.encrypt(raw, "*")

    return enc
  
  def decrypt (self, enc, secret) :

    des = pyDes.des(secret)
    raw = des.decrypt(enc, "*")

    return raw

  # #########################################################

  # ACTUAL OAUTH STUFF
  
  def do_oauth_auth (self, min_perms=None, redir=None) :

    # GENERATE CRUMB...
    
    # WHAT WOULD CROWLEY DO ?
    
  def do_token_dance (self, perms=None) :

    # WHAT WOULD CROWLEY DO ?
    
    extra = self.request.get('extra')
    e_params = {}
  
    if extra and extra != '' :
    	extra = urlparse(extra)
        e_params = dict([part.split('=') for part in extra[2].split('&')])

    crumb = urllib.unquote(e_params['crumb'])
    
    if not self.validate_crumb(None, 'auth_my_oauth', crumb) :
    	return False

    # WHAT WOULD CROWLEY DO ?

    # GET USER HERE...UH, HOW?

    # SAME WITH PERMS...
    
    if not user :

    	args = {
        'password' : self.generate_password(),
        'user_token' : user_token,
        'user_secret' : user_secret,
        'perms' : user_perms,
        }
      
        user = User.create(args)

    else :
    
    	credentials = {
          'user_token' : consumer_token,
          'user_secret' : consumer_secret,
          'perms' : user_perms,          
        }
    
        User.update_credentials(user, credentials)

    self.response.headers.add_header('Set-Cookie', self.ffo_cookie(user))
    self.response.headers.add_header('Set-Cookie', self.fft_cookie(user))    

    if e_params.has_key('redir') :
    	self.redirect(e_params['redir'])
    else :
  	self.redirect("/")
          
  def check_token (self, min_perms) :

    # WHAT WOULD CROWLEY DO ?

  def api_call(http_method, **kwargs) :

    # UH, SOMETHING LIKE THIS I GUESS...
    
    try:
      return json.loads(oauth_response(oauth_request(
        url, token, http_method=http_method, parameters=kwargs
        )))

    except:
      pass

    return None
  
