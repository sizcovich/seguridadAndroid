import BaseHTTPServer, SimpleHTTPServer
import ssl
import logging
import traceback
import json
from sets import Set
import uuid
import os
import base64
from urlparse import urlparse, parse_qs, parse_qsl
from Crypto.Cipher import AES
import numpy as np

established_session_keys = Set()

class ServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

	def check_user(self,email,password,_uuid):
		with open('users_file','r') as users_file:
			json_loaded = json.load(users_file)
			email_key = json_loaded.get('email',None)
			return email_key and (email_key['uuid'] == _uuid or email_key['password'] == password ) 
		raise Exception("problem reading user's file")

	def get_user_session_key(self):
		_uuid = str( uuid.uuid4().bytes) 
		established_session_keys.add( _uuid )
		return _uuid

	def check_authorized(self,session_key):
		return session_key in established_session_keys

	def save_sync(self,email,session_key,content):
		if not self.check_authorized(session_key):
			return 401
		else:
			with open('sync_file','r+') as sync_file:
				json_loaded = json.load(sync_file)
				sync_file.seek(0)
				json_loaded[email] = content
				json.dump(json_loaded,sync_file)
				sync_file.flush()
		return 200

	def get_sync(self,email,session_key):
		if not self.check_authorized(session_key):
			return None
		return self.get_stored_sync(email)

	def get_stored_sync(self,email):
		with open('sync_file','r') as sync_file:
			json_loaded = json.load(sync_file)
			if not json_loaded.get(email,None):
				#return empty dictionary when no history
				return []
			return json_loaded[email]
		raise Exception("problem reading sync_file")

	def register(self,content):
		email = content['email']
		password = content['password']
		uuid = content['uuid']
		with open('users_file','r+') as users_file:
			json_loaded = json.load(users_file)
			users_file.seek(0)
			json_loaded['email'] = {'uuid':uuid,'password':password}
			json.dump(json_loaded,users_file)
			users_file.flush()

	def encrypt(self,value):
		enc = AES.new("0395a67c9aa847a756daa8535917e805", AES.MODE_CBC, "0000000000000000")
		return base64.b64encode( enc.encrypt(value) ) 

	def decrypt(self,value):
		decryptor = AES.new("0395a67c9aa847a756daa8535917e805", AES.MODE_CBC, "0000000000000000")
		return decryptor.decrypt(base64.b64decode(value) )

	#only has POST
	def do_POST(self):
		try:
			length = int(self.headers['Content-Length'])
			content = self.rfile.read(length).decode('utf-8')
			if self.path == '/login' or self.path == '/register':
				content =  dict( parse_qsl(content) )
				print content
			if  self.path == '/login': 
			 	email = content['email']
			 	password = content['password']
			 	_uuid = content['uuid']
				if self.check_user(email,password,_uuid):
					self.send_response(200) 
					self.send_header("Session", self.encrypt(self.get_user_session_key()))
				else:
	 				self.send_response(400)
			elif self.path == '/register':
				self.register(content)
				self.send_response(200)
	 		elif self.path.startswith( '/sync' ):
	 			#cast urls as list of strings
	 			#content = np.array(content)
	 			query_components = parse_qs(urlparse(self.path).query)
	 			email = query_components['email'][0]
	 			session_key = self.decrypt(query_components['session_key'][0])
				status_code = self.save_sync(email,session_key,json.loads(content))
				self.send_response(status_code)
			else:
				self.send_response(404)
		except:
			logging.warning(  traceback.format_exc() )
			self.send_response(500)
		self.end_headers()


	def do_GET(self):
		try:
				if self.path.startswith( '/sync' ):
					query_components = parse_qs(urlparse(self.path).query)
					print query_components
					response = self.get_sync(query_components['email'][0],self.decrypt(query_components['session_key'][0]))
					print response
					if response is None:
						self.send_response(401)
					else: 
						self.send_response(200)
						self.end_headers()
						self.wfile.write( json.dumps(response) )						
				else:
					self.send_response(404)
		except:
			logging.warning(  traceback.format_exc() )
			self.send_response(500)
		self.end_headers()

if not os.path.exists('users_file'):
	#initializte users file
	with open('users_file', mode='w') as f:
	    json.dump({}, f)

if not os.path.exists('sync_file'):
	#initializte sync file
	with open('sync_file', mode='w') as f:
	   json.dump({}, f)
	   
httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 8888), ServerHandler)
httpd.serve_forever()
