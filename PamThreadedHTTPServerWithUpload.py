#!/usr/bin/env python3

"""Threaded HTTP Server With Upload.

This module builds on BaseHTTPServer by implementing the standard GET
and HEAD requests in a fairly straightforward manner.

"""

import os, struct
import posixpath
import http.server as BaseHTTPServer
from http.server import HTTPServer
from http.cookies import SimpleCookie
import urllib
import cgi
import shutil
import mimetypes
import re
from socketserver import ThreadingMixIn
import email
import socket
import argparse
from cgi import parse_multipart
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto import Random
import hashlib
import hmac
from io import StringIO
import logging
import pam
import string
import datetime
import random
from decimal import Decimal
import time
import grp, pwd

logger=logging.getLogger()
logger.setLevel(logging.DEBUG)

def randomString(stringLength=64):
	letters=string.hexdigits
	return ''.join(random.choice(letters) for i in range(stringLength))

def genRefCookie(location):
	global cookiesecure
	cookie=SimpleCookie()
	cookie['p_ref'] = location
	cookie['p_ref']['expires'] = 60 * 60* 24
	cookie['p_ref']['path'] = "/"
	cookie['p_ref']['httponly'] = True

	if cookiesecure:
		cookie['p_ref']['secure'] = True

	return cookie


def genCookie(secret_key, username, ipaddress="127.0.0.1", invalid=False):
	global cookiesecure
	#expiration=str(datetime.datetime.now()+datetime.timedelta(minutes=60))
	expiration=str(datetime.datetime.now()+datetime.timedelta(minutes=60))
	params="username="+username + "&expiration=" + expiration + "&ipaddress=" + str(ipaddress)
	salt=randomString(stringLength=16)
	# Username is a pepper, salt is random salt and secret_key is global
	if invalid==False:
		if checkip==True:
			signature=hmac.new(ipaddress.encode() + username.encode() + salt.encode()+secret_key, params.encode(), hashlib.sha256).hexdigest()
		else:
			signature=hmac.new(username.encode() + salt.encode()+secret_key, params.encode(), hashlib.sha256).hexdigest()
			
	else:
		signature="1234"
	cookie=SimpleCookie()
	cookie['p_auth'] = params + "&sig=" + salt+signature
	cookie['p_auth']['expires'] = 60*60*24
	cookie['p_auth']['path'] = "/"
	cookie['p_auth']['httponly'] = True
	if cookiesecure:
		cookie['p_auth']['secure'] = True
	return cookie
		
def validateCookie(secret_key, cookie, clientip):
	print("In Validate Cookie")

	try:
		temp=cookie
		cookie=temp.split("&sig=")[0]
		sig1=temp.split("&sig=")[1]
		salt=sig1[0:16]		
		username=""
		for x in cookie.split("&"):
			y=x.split("=")
			if y[0]=="username":
				username=y[1]
				break
		print("Username", username)
		print("IP Address", clientip)

		if checkip==True:
			sig2=hmac.new(clientip.encode() + username.encode() + salt.encode()+secret_key, cookie.encode(), hashlib.sha256).hexdigest()
		else:
			sig2=hmac.new(username.encode() + salt.encode()+secret_key, cookie.encode(), hashlib.sha256).hexdigest()
	
		if not sig1==(salt+sig2):
			print("Signatures Don't Match")
			return False
		temp2=cookie.split("&")
		for data in temp2:
			key=data.split("=")[0]
			value=data.split("=")[1]	
			if key=="expiration":
				expirationdate=datetime.datetime.strptime(value.split(".")[0], "%Y-%m-%d %H:%M:%S")
				currentdate=datetime.datetime.now()
				print(currentdate, expirationdate)
				if currentdate>expirationdate:
					print("Cookie Expired")
					return False
			'''if key=="ipaddress":
				if not clientip==value:
					print("IP Addresses Don't Match")
					return False'''
				
		return True
	except Exception:
		#print("Invalid Cookie", Exception)
		print("Invalid Cookie", logger.error(str(Exception), exc_info=True))
		return False



def sha2_hash(hash_string):
	return hashlib.sha256(hash_string.encode())

class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    pass

class MainProcess(BaseHTTPServer.BaseHTTPRequestHandler):

	# Put Method Unsupported; probably need to add an error message at some point.
	def do_PUT(self):
		if not self.react_site():		
			return None
		self.do_GET()						

	def do_GET(self):
		print("Self.Path in DO_GET = " + self.path)
		if not self.react_site():		
			return None					

		"""Serve a GET request."""
		f = self.send_head()
		if f:
			f.seek(0)
			temp=f.read()
			#print(temp)
			self.copyfile(temp, self.wfile)
			f.close()
		else:
			self.send_response(301)
			temp=self.path.split("/")
			data=len(temp)-1
			path=""
			counter=0
			for x in temp:
				path=path+"/" + x
				counter+=1
				if counter==data:
					break
			path=path.replace("//", "/")
			print(path)
			self.send_header("Location", path)
			self.end_headers()
			return None

			
	def do_HEAD(self):
		"""Serve a HEAD request."""
		global secret_key
		global pamenabled
		cookies=SimpleCookie(self.headers.get('Cookie'))

		path=self.path
		if pamenabled==True:
			if cookies.get("p_auth") == None:
				self.send_response(302)
				self.send_header("Location", "/authentication_services")
				refCookie=genRefCookie(self.path)
				self.send_header("Set-cookie", refCookie.output(header='', sep=''))
				self.end_headers()
				return None
			else:
				cookie=cookies.get("p_auth").value
				result=validateCookie(secret_key, cookie, self.client_address[0])
				if result==False:
					self.send_response(302)
					self.send_header("Location", "/authentication_services")
					refCookie=genRefCookie(self.path)
					self.send_header("Set-cookie", refCookie.output(header='', sep=''))

					self.end_headers()
					return None

		f = self.send_head()
		if f:
			f.close()

	def do_POST(self):

		global secret_key
		global pamenabled
		f = StringIO()
		cookies=SimpleCookie(self.headers.get('Cookie'))

		path=self.path
		if pamenabled==True and not self.path=="/authentication_services":
			if cookies.get("p_auth") == None:
				self.send_response(302)
				self.send_header("Location", "/authentication_services")
				refCookie=genRefCookie(self.path)
				self.send_header("Set-cookie", refCookie.output(header='', sep=''))
				self.end_headers()
				return None
			else:
				cookie=cookies.get("p_auth").value
				result=validateCookie(secret_key, cookie, self.client_address[0])
				if result==False:
					self.send_response(302)
					self.send_header("Location", "/authentication_services")
					self.end_headers()
					return None

		try:

			"""Serve a POST request."""
			r, info = self.deal_post_data()
			print(r, info, "by: ", self.client_address)
			if r=="301self":
				self.send_response(301)
				self.send_header("Location", self.path)

				self.end_headers()
				return None
			if r=="301below":
				self.send_response(301)
				temp=self.path.split("/")
				data=len(temp)-1
				path=""
				counter=0
				for x in temp:
					path=path+"/" + x
					counter+=1
					if counter==data:
						break
				path=path.replace("//", "/")
				print(path)
				self.send_header("Location", path)

				self.end_headers()
				return None
			if r=="3012below":
				self.send_response(301)
				temp=self.path.split("/")
				data=len(temp)-2
				path=""
				counter=0
				for x in temp:
					path=path+"/" + x
					counter+=1
					if counter==data:
						break
				path=path.replace("//", "/")
				print(path)
				self.send_header("Location", path)

				self.end_headers()
				return None

			if r=="Cookie":
				self.send_response(301)
				self.send_header("Set-cookie", info.output(header='', sep=''))
				#self.send_header("Location", "/")
				if cookies.get("p_ref")==None:
					self.send_header("Location", "/")
				else:
					cookie=cookies.get("p_ref").value
					if cookie=="/authentication_services":
						self.send_header("Location", "/")
					else:			
						self.send_header("Location", cookie)
				self.end_headers()

				return None
			if r=="Unauthenticated":
				f.write('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
				f.write("<html lang=\"en\">\n<meta charset=\"utf-8\"/>\n<title>Unauthenticated</title>\n")
				f.write("<body>\n<h2>Wrong Username, Password, and/or Group</h2>\n")
				if self.headers.get('referer'):
					f.write("<br><a href=\"%s\">back</a>" % self.headers.get('referer'))
				else:
					f.write("<br><a href=\"/\">back</a>")

				f.write("</body></html>")
				self.send_response(401)
				self.send_header("Content-type", "text/html")
				length = f.tell()
				self.send_header("Content-Length", str(length))
				self.end_headers()
				if f:
					f.seek(0)
					temp=f.read()
					self.copyfile(temp, self.wfile)
					f.close()
				return None


			if r==True or r==False:
				f.write('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
				f.write("<html lang=\"en\">\n<meta charset=\"utf-8\"/>\n<title>Status Result Page</title>\n")
				f.write("<body>\n<h2>Status Result Page</h2>\n")
				f.write("<hr>\n")
				if r:
					f.write("<strong>Success:   </strong>")
				else:
					f.write("<strong>Failed:   </strong>")
				f.write(str(info))
				f.write("<br><a href=\"%s\">back</a>" % self.headers['referer'])
				f.write("</body></html>")
				length = f.tell()
				if r==True:
					self.send_response(200)
				else:
					self.send_response(500)
				self.send_header("Content-type", "text/html")
				username=""
				pauth=cookies.get("p_auth").value
				temp=pauth.split("&")
				for x in temp:
					temp2=x.split("=")
					if temp2[0]=="username":
						username=temp2[1]
						break
				cookie=genCookie(secret_key, username, self.client_address[0])
				self.send_header("Set-cookie", cookie.output(header='', sep=''))

				self.send_header("Content-Length", str(length))
				self.end_headers()
				if f:
					f.seek(0)
					temp=f.read()
					self.copyfile(temp, self.wfile)
					f.close()
				return None
		except Exception as e:
			print("In Exception", logger.error(str(e), exc_info=True))
			self.send_response(500)
			self.end_headers()


	def react_site(self):
		global secret_key
		print("In React Site")
		cookies=SimpleCookie(self.headers.get('Cookie'))

		path=self.path
		temp=self.path.replace("//", "/")

		print("React Site 1")		
		if not self.path==temp:
			#print(self.path, temp)
			self.send_response(301)
			#temp=self.path.replace("//", "/")
			temp2=temp
			while True:
				temp2=temp2.replace("//", "/")
				if temp2==temp:
					break
				else:
					temp=temp2
			self.send_header("Location", temp)
			self.end_headers()

			return False
		print("React Site 2")
		if pamenabled==True:
			print("React Site 2a")

			print("React Site 2b")

			if path=="/authentication_services":
				self.handle_auth()
				return None

			print("React Site 2c")

			if cookies.get("p_auth") == None:
				print("No Cookie P_AUTH")
				self.send_response(302)
				self.send_header("Location", "/authentication_services")
				refCookie=genRefCookie(self.path)
				self.send_header("Set-cookie", refCookie.output(header='', sep=''))

				self.end_headers()
				return None
			else:
				print("Validating Cookie")
				cookie=cookies.get("p_auth").value
				result=validateCookie(secret_key, cookie, self.client_address[0])
				if result==False:
					print("Cookie did not validate")
					self.send_response(302)
					self.send_header("Location", "/authentication_services")
					refCookie=genRefCookie(self.path)
					self.send_header("Set-cookie", refCookie.output(header='', sep=''))
					self.end_headers()
					return False

		print("React Site 3")
		return True


	def handle_auth(self):
		global banner
		print("In Handle Auth")
		f = StringIO()

		f.write('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')

		f.write("<html lang=\"en\">\n<meta charset=\"utf-8\"/>\n<title>Authenticate</title>\n")
		f.write('''<script>
function checkSubmit() 
{
	

	if (document.getElementById('password-input').value=='' && document.getElementById('username-input').value=='')
	{
		alert("Username and Password is Empty!!!");
		return false;
	}
	if (document.getElementById('password-input').value=='')
	{
		alert("Password Empty");
		return false;
	}
	else if (document.getElementById('username-input').value=='')
	{
		alert("Username is Empty");
		return false;
	}
	return true;

}
</script>''')

		f.write("<style>button.link { background: none!important; borner:none; padding: 0!important; font-family: arial, sans-serif; corlor: #069; text-decoration: underline; cursor: pointer; margin: 0; color: blue}</style>")

		f.write("<body>")
		f.write("<B>Authenticate</B>\n")
		f.write("<hr>\n")
		f.write("""<form ENCTYPE="multipart/form-data" method="post">""")
		f.write("<table><tr>")

		f.write("""<td><b>Username:  </b></td><td><input type="username" id="username-input" name="username" readonly onfocus="this.removeAttribute('readonly');"/></td>\n""")
		f.write("</tr><tr>")
		f.write("""<td><b>Password:  </b></td><td><input type="password" name="password" autocomplete="none" id="password-input" readonly onfocus="this.removeAttribute('readonly');"/></td>\n""")
		f.write("</table>")
		f.write("""</br></br><input type="submit" value="Submit" name="Submit" onClick="return checkSubmit()"/>\n</form>\n""")
		try:
			f.write("<p style=\"font-family:courier;\"><pre>")
			bannerfile=open(banner, "rb")
			data=bannerfile.read()
			f.write(data.decode("cp437"))
			f.write("</pre></p>")
			bannerfile.close()
		except Exception:
			print("Error reading banner")
			print("In Banner", logger.error(str(Exception), exc_info=True))
		

		f.write("</body>")
		f.write("</html>")
		f.seek(0)
		temp=f.read()
		self.send_response(200)
		self.send_header("Content-type", "text/html")
		self.send_header("Cache-Control", "no-store")

		self.send_header("Content-Length", len(temp))
		self.end_headers()

		self.copyfile(temp, self.wfile)
		f.close()

	
	def deal_post_data(self):
		print("In Deal Post")

		contenttype=self.headers.get('content-type')
		returned=self.deal_post_mime()
		return returned

	def deal_post_plain(self):
		return("False", "Encoding type text/plain is not supported")

		
	def deal_post_mime(self):
		global secret_key
		print("In deal post mime")
		if workingpath==None:
			path=self.translate_path(self.path)
		else:
			path=workingpath

		temp=self.headers['Content-Type'].replace("form-data", "mixed")
		data="MIME-Version: 1.0\nContent-Type: " + temp + "\n\nDummyData\n"
		try:
			length = int(self.headers['content-length'])
		except:
			print("Exception, no length data")
			return("False", "Error Getting Content-Length")
		if length<=(4096*1048576):
			temp=self.rfile.read(length)
			data=data+temp.decode("cp437")
		else:
			print("Upload Limit Error")
			return (False, "Uploads are limited to 4 GB.")
		try:
			msg=email.message_from_string(data)
		except Exception as e:
			print("Exception Decoding Mime Message")
			return(False, "Error Decodong Message")
		try:
			encryptionkey=""
			foundencryption=False
			validatehash=""
			print(self.path)
			if self.path=="/authentication_services":
				print("Trying to Authenticate")
				username=""
				password=""
				if msg.is_multipart():
					for item in msg.get_payload():
						header=item.get("content-disposition")
						value, params = cgi.parse_header(header)
						upload=params.get('name')
						if upload=="username":
							username=item.get_payload()
						if upload=="password":
							password=item.get_payload()

				p=pam.pam()
				try:
					if authorizedGroup=="":
						isAuthorized=True
					else:
						groups=grp.getgrnam(authorizedGroup).gr_mem
						if username in groups:
							isAuthorized=True
						else:
							isAuthorized=False
				except Exception:
					isAuthorized=False
					print("Exception in Authorization", exception)
					pass
				
				
				#groups=[g.gr_name for g in grp.getgrall() if username in g.gr_mem]
				'''gid=pwd.getpwnam(username).pw_gid
				groups.append(grp.getgrgid(gid).gr_name)
				print(groups)'''
				#print(groups)


				isAuthenticated=p.authenticate(username, password)
				print("User ", username, " is authenticated ", str(isAuthenticated))
				if isAuthenticated and isAuthorized:
					cookie=genCookie(secret_key, username, self.client_address[0])
					return ("Cookie", cookie)				
				else:
					return("Unauthenticated", "Authentication Failure")

			if msg.is_multipart():
				for item in msg.get_payload():
					header=item.get("content-disposition")
					value, params = cgi.parse_header(header)
					upload=params.get('name')

					if upload=="encryptionkey":
						encryptionkey=item.get_payload()
						if not encryptionkey=="":
							datahash=sha2_hash(encryptionkey)
							datadigest=datahash.digest()
							validatehash=sha2_hash(datahash.hexdigest())
							datadigest=datadigest[0:16]
							encryptkey=datadigest
							encryptkeydigest=datahash.hexdigest()
							foundencryption=True


			if msg.is_multipart():
				for item in msg.get_payload():
					header=item.get("content-disposition")
					value, params = cgi.parse_header(header)
					upload=params.get('name')
					if upload=="Signout":
						print("In Signout")
						cookie=SimpleCookie(self.headers.get('Cookie'))
						'''cookie['p_ref'] = self.path
						cookie['p_ref']['expires'] = "Thu, 01 Jan 1970 00:00:00 GMT"
						cookie['p_ref']['path'] = "/"
						cookie['p_ref']['httponly'] = True

						if cookiesecure:
							cookie['p_ref']['secure'] = True'''

						#cookie['p_ref']['secure'] = True
						wrongkey = randomString().encode()
						# This should never happen
						while secret_key==wrongkey:
							wrongkey = randomString().encode()

						cookie=genCookie(wrongkey, "signout", self.client_address[0])
						'''cookie['p_auth']="Expired"
						cookie['p_auth']['expires'] = "Thu, 01 Jan 1970 00:00:00 GMT"
						cookie['p_auth']['path'] = "/"
						cookie['p_auth']['httponly'] = True

						if cookiesecure:
							cookie['p_auth']['secure'] = True

						#cookie['p_auth']['secure'] = True'''
						return("Cookie", cookie)


			if msg.is_multipart():
				for item in msg.get_payload():
					header=item.get("content-disposition")
					value, params = cgi.parse_header(header)
					upload=params.get('name')
					if upload=="ViewFile":
						print("In View File")
						datapath=item.get_payload()
						if workingpath==None:
							path = self.translate_path(self.path)
						else:
							path = workingpath + self.path
						f = None
						path=path.replace("//", "/")
						path=urllib.parse.unquote(path)

						ctype = self.guess_type(path)
						try:
							infile = open(path, 'rb')
							print(path)
						except IOError as err:
							print("Error Reading File", logger.error(str(err), exc_info=True))
							return(False, "Error Reading File; " + str(err).split(":")[0])

						fs = os.fstat(infile.fileno())

						if foundencryption==False:	
							print("Encryption Not Found")
							self.send_response(200)
							self.send_header("Content-Length", os.path.getsize(path))
							cookies=SimpleCookie(self.headers.get('Cookie'))
							username=""
							pauth=cookies.get("p_auth").value
							temp=pauth.split("&")
							for x in temp:
								temp2=x.split("=")
								if temp2[0]=="username":
									username=temp2[1]
									break
							print("Sending IP Address", self.client_address[0])
							cookie=genCookie(secret_key, username, self.client_address[0])

							self.send_header("Content-type", ctype)
							self.send_header("Set-cookie", cookie.output(header='', sep=''))


							self.end_headers()

							while True:
								data=infile.read(65536)
								if not data:
									break
								self.wfile.write(bytearray(data))
							return("Ignore", "View File without encryption")

						else:
							print("Encryption Found")
							cookies=SimpleCookie(self.headers.get('Cookie'))
							username=""
							pauth=cookies.get("p_auth").value
							temp=pauth.split("&")
							for x in temp:
								temp2=x.split("=")
								if temp2[0]=="username":
									username=temp2[1]
									break

							testvalidatehash = infile.read(64)
							temp=validatehash.hexdigest().encode()
							if not temp==testvalidatehash:
								infile.close()
								return(False, "Encryption Signatures Do Not Match; Most Likely Wrong Password")
							origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
							self.send_response(200)

							self.send_header("Content-Length", origsize)
							cookie=genCookie(secret_key, username, self.client_address[0])
							self.send_header("Set-cookie", cookie.output(header='', sep=''))

							self.send_header("Content-type", ctype)

							self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
							self.end_headers()

							#print(testvalidatehash, str(validatehash.hexdigest().encode()))
							iv = infile.read(16)
							decryptor = AES.new(encryptkey, AES.MODE_CBC, iv)
							chunksize=65552
							while True:
								chunk = infile.read(chunksize)
								if len(chunk)==0:
									break
								if len(chunk)==chunksize:
									decrypted=decryptor.decrypt(chunk)
									self.wfile.write(decrypted[0:65536])
								else:
									temp=decryptor.decrypt(chunk)
									temp2=len(temp)-16
									self.wfile.write(temp[0:temp2])
							infile.close()
							return("Ignore", "View file with encryption")

						infile.close()

			filecount=0
			if msg.is_multipart():
				for item in msg.get_payload():
					header=item.get("content-disposition")
					value, params = cgi.parse_header(header)
					upload=params.get('name')
					print(value, params)
					if upload=="upload" and not params.get('filename')=="":
						print("In upload file")
						datapath=params.get('filename')
						print("Datapath is ", datapath)
						if workingpath==None:
							path = self.translate_path(self.path) + "/" + datapath
						else:
							path = workingpath + self.path + "/" + datapath

						#path = self.translate_path(self.path)
						try:
							if datapath[:-1]=="/":
								return (False, "No File Specified for Upload!!!") 
							if ".." in datapath:
								return (False, "Double dots detected in filename!!!")
							if datapath[0]=='/':
								return (False, "First Character is a slash")

							payload=item.get_payload()

							out = open(path, 'wb')
						
							if encryptionkey=="":

								out.write(payload.encode("cp437"))
							else:
								try:
									iv=Random.new().read(AES.block_size)
									encryptor=AES.new(encryptkey, AES.MODE_CBC, iv)
									filesize=len(payload)
									print(validatehash.hexdigest().encode())
									out.write(validatehash.hexdigest().encode())
									out.write(struct.pack('<Q', filesize))
									out.write(iv)
									chunksize=65536
									for x in range(int(filesize/chunksize) +1):
										temp=x*chunksize
										temp2=(x+1)*chunksize
										chunk=payload[temp:temp2]
										if len(chunk)==0:
											break
										elif len(chunk)%16 !=0:
											chunk += ' ' * (16 - len(chunk) %16)
										ct_bytes=encryptor.encrypt(pad(chunk.encode("cp437"), AES.block_size))
										out.write(ct_bytes)
								except Exception:
									print("In Exception", logger.error(str(Exception), exc_info=True))
									return(False, "Error Decrypting File")
							out.close()
							filecount=filecount+1
							returned=("301self", "File Written")
						except IOError:
							return (False, "Can't create file to write.")				
					elif upload=="createdir" and not item.get_payload()=="":
						print("In Create Dir")
						#path = self.translate_path(self.path)
						fn=item.get_payload().split("\n")
						fntemp=fn[0]
						fn=path+'/'+self.path + "/" + fn[0]
						fn=fn.replace('//', '/')
						try:
							if fn==(path + "/"):
								return (False, "No Directory Specified!!!") 
							if ".." in fn:
								return (False, "Double dots detected in filename!!!")
							if fntemp[0]=='/':
								return (False, "First Character is a slash")
							os.mkdir(fn)
							return("301self", 'Okay')
						except IOError:
							return (False, "Can't create directory.")
					elif upload=="deletefile" and not item.get_payload()=="":
						print("In Delete File")
						datapath=item.get_payload()

						if workingpath==None:
							path = self.translate_path(self.path)
						else:
							path = workingpath + "/" + self.path
						if datapath==path.split("/")[-1]:
							fn=path
						else:
							fn=datapath
						fn=fn.replace("//", "/")
						fn=urllib.parse.unquote(fn)
						print("FN: ", fn)
						try:
							if ".." in fn:
								return (False, "Double dots detected in filename!!!")
							if datapath[0]=='/':
								return (False, "First Character is a slash")
							if os.path.isfile(fn):
								try:
									os.remove(fn)
									return("301below", "File deleted")
								except Exception as err:
									print("Error Removing File", logger.error(str(err), exc_info=True))
									return(False, "Error Removing File; " + str(err).split(":")[0])
									
						except IOError:
							return (False, "File not deleted")
					elif upload=="removedir" and not item.get_payload()=="":
						print("In Remove Dir")
						datapath=item.get_payload()

						if workingpath==None:
							path = self.translate_path(self.path)
						else:
							path = workingpath + "/" + self.path
						fn=path
						fn=fn.replace("//", "/")
						fn=urllib.parse.unquote(fn)
						print("FN: ", fn)
						try:
							if ".." in fn:
								return (False, "Double dots detected in filename!!!")
							if datapath[0]=='/':
								return (False, "First Character is a slash")
							if os.path.isdir(fn):
								try:
									os.rmdir(fn)
								except Exception as err:
									print("Error Removing Directory", logger.error(str(err), exc_info=True))
									return(False, "Error Removing Directory; " + str(err).split(":")[0])
								
								return("3012below", "File deleted")
							else:
								return(False, "Error Removing Directory" + fn)
								
						except IOError:
							return (False, "File not deleted")
			if filecount>0:
				return returned
		except Exception as e:					
			print("In Exception", logger.error(str(e), exc_info=True))
			return(False, "POST Form Error Secondary")

		return(False, "POST Form Error Main")



	def send_head(self):
		if workingpath==None:
			path = self.translate_path(urllib.parse.unquote(self.path))
		else:
			path = workingpath + urllib.parse.unquote(self.path)

		f = None
		if "?" in self.path:
				temp=self.path.split("?")
				self.send_response(301)
				
				self.send_header("Location", temp[0])
				self.end_headers()
				return None
		if os.path.isdir(path):
			if not self.path.endswith('/'):
				# redirect browser - doing basically what apache does
				self.send_response(301)
				self.send_header("Location", self.path + "/")
				self.end_headers()
				return None				
			else:
				temp=path+self.path
				return self.List_Directory(path)
		path=path.replace("//", "/")
		path=urllib.parse.unquote(path)

		ctype = self.guess_type(path)
		try:
			# Always read in binary mode. Opening files in text mode may cause
			# newline translations, making the actual size of the content
			# transmitted *less* than the content-length!
			f = open(path, 'rb')
		except IOError:
			#self.send_error(404, "File not found")
			#self.send_response(404)
			#self.send_header("Location", self.path + "/")
			#self.end_headers()

			return None
		self.send_response(200)
		self.send_header("Content-type", ctype)
		fs = os.fstat(f.fileno())
		self.send_header("Content-Length", str(fs[6]))
		self.send_header("Cache-Control", "no-store")

		self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
		cookies=SimpleCookie(self.headers.get('Cookie'))
		username=""
		pauth=cookies.get("p_auth").value
		temp=pauth.split("&")
		for x in temp:
			temp2=x.split("=")
			if temp2[0]=="username":
				username=temp2[1]
				break
		cookie=genCookie(secret_key, username, self.client_address[0])
		self.send_header("Set-cookie", cookie.output(header='', sep=''))
		self.end_headers()
		return f

	def List_Directory(self, path):
		f = StringIO()

		try:
			list = os.listdir(path)
		except os.error:
			self.send_error(403, "Permission Error")
			return None
		list.sort(key=lambda a: a.lower())
		displaypath = cgi.escape(urllib.parse.unquote(self.path))

		f.write('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
		f.write("<html lang=\"en\">\n<meta charset=\"utf-8\"/><title>Directory listing for %s</title>\n" % displaypath)
		f.write('''<script>
function clearKey() 
{
	var element;
	/*element=document.getElementById("encryptionkeyid");
	element.parentNode.removeChild(element);
	element=document.getElementById('createdir-input')
	element.parentNode.removeChild(element);
	element=document.getElementById("uploadid");
	element.parentNode.removeChild(element); */

	document.getElementById("encryptionkeyid").value="";
	document.getElementById('createdir-input').value="";
	document.getElementById("uploadid").value="";
	return true;

}

function clearExceptEncryption() 
{
	var element;
	/*element=document.getElementById('createdir-input')
	element.parentNode.removeChild(element);
	element=document.getElementById("uploadid");
	element.parentNode.removeChild(element);*/

	document.getElementById('createdir-input').value="";
	document.getElementById("uploadid").value="";

	return true;

}

function checkUpload()
{
	var temp, element;
	var  myHeaders = new Headers();
	temp=document.getElementById('uploadid').value!='';
	if(temp==false)
	{
		alert("No File Name Specified")
		return temp;
	}
	else
	{
		//document.getElementById("directoryid").enctype="application/x-www-form-urlencoded";
		///myHeaders.set("p_operation", "upload")
		element=document.getElementById('createdir-input')
		element.parentNode.removeChild(element);

	}
	return temp;
}

function checkDirectory()
{
	var temp, element;
	temp=document.getElementById('createdir-input').value!='';
	if(temp==false)
	{
		alert("No Directory Name Specified")
	}
	else
	{
		/*element=document.getElementById("encryptionkeyid");
		element.parentNode.removeChild(element);
		element=document.getElementById("uploadid");
		element.parentNode.removeChild(element);*/

		document.getElementById("encryptionkeyid").value="";
		document.getElementById("uploadid").value="";

	}
	return temp;
}


</script>		''')		


		f.write("<style>table.light { border-collapse: collapse; } table.light, td.light, th.light { border: 1px solid #F5F5F5; } button.link { background: none!important; borner:none; padding: 0!important; font-family: arial, sans-serif; color: #069; text-decoration: underline; cursor: pointer; margin: 0; color: blue}</style>")

		f.write("<form ENCTYPE=\"multipart/form-data\" onclick=\"clearKey()\" method=\"post\"><button type=\"submit\" value=\"Signout\" name=\"Signout\">Sign Out</button></form>\n")

		f.write("<body>\n<h2>Directory listing for %s</h2>\n" % displaypath)
		f.write("<hr>\n")
		f.write("""<form id="directoryid" ENCTYPE="multipart/form-data" method="post" autocomplete="off" "accept-charset=utf-8">""")
		f.write("<table><tr>")
		f.write("<td><b>Encryption Key: </b></td><td><input type=\"password\" id=\"encryptionkeyid\" name=\"encryptionkey\" readonly onfocus=\"this.removeAttribute('readonly');\" /></td>\n")
		f.write('<td><b>Upload File: </b></td><td><input id="uploadid" name="upload" id="upload-input" type="file" multiple/></td>')
		#f.write("""<td><input type="submit" id="uploadid" value="Upload" name="Upload" onClick="return document.getElementById('uploadid').value!=''"/></td>\n""")
		f.write("""<td><input type="submit" id="uploadid" value="Upload" name="Upload" onClick="return checkUpload()"/></td>\n""")
		f.write("</tr><tr>")
		f.write("""<td><b>Make Directory: </b></td><td><input type="text" id="createdir-input" name="createdir" readonly onfocus="this.removeAttribute('readonly');" /></td>\n""")

		f.write("""<td><input type="submit" value="Create Directory" name="mkdir" onClick="return checkDirectory()"/></td>\n""")
		f.write("</tr></table>")
		f.write("<hr>\n<ul>\n")
		f.write("<table class=\"light\">")
		f.write('<tr>')
		f.write("""<td class="light" style="min-width:200px"><center><b>Name</b></center></td>""")
		f.write("""<td class="light" style="min-width:100px"><center><b>Size</b></center></td>""")
		f.write("""<td class="light" style="min-width:100px"><center><b>Last Modified</b></center></td>""")
		f.write("""<td class="light" style="min-width:100px"><center><b>Action</b></center></td>""")
		f.write("""<td class="light" style="min-width:100px"><center><b>Save As Link (Does Not Support Encryption)</b></center></td></tr>""")

		if not displaypath=="/":
			f.write('<td class="light"><button class="link" onclick=\"clearKey()\" type=\"submit\" value=\"..\" formmethod=\"get\" formaction=\"..\">..</button><br/></td>\n')
			f.write("</tr>")
		for name in list:
			fullname = os.path.join(path, name)
			displayname = linkname = name
			# Append / for directories or @ for symbolic links
			form=0
			if os.path.isfile(fullname):
				displayname = name
				linkname = name
				form=1

			elif os.path.isdir(fullname):
				displayname = name + "/"
				linkname = name + "/"
				form=2
			elif os.path.islink(fullname):
				displayname = name + "@"
				form=3
			if form==1:
				#f.write('<a href=\"%s\">%s</a>   ' % (urllib.parse.quote(linkname), urllib.parse.quote(linkname)))
				f.write('<tr class="light">')
				f.write('<td class="light"><button onclick=\"clearExceptEncryption()\" formaction=\"%s\" class="link" type=\"submit\" value=\"%s\" name=\"ViewFile\">%s</button></td>\n' % (urllib.parse.quote(linkname), urllib.parse.quote(linkname), cgi.escape(displayname)))
				filesize=os.path.getsize(fullname)
				if filesize>=1073741824:
					filesizetemp=Decimal(filesize/1073741824)
					filesizetemp=round(filesizetemp,1)
					#filesizetemp=(filesize-filesize%1048756)/1073741824
					filetext=str(filesizetemp) + "G"
				elif filesize>=1048576:
					#filesizetemp=(filesize-filesize%1024)/1048576
					filesizetemp=Decimal(filesize/1048576)
					filesizetemp=round(filesizetemp,1)

					filetext=str(filesizetemp) + "M"
				elif filesize>=1024:
					filesizetemp=Decimal(filesize/1024)
					filesizetemp=round(filesizetemp,1)
					filetext=str(filesizetemp) + "K"
				else:
					filetext=str(filesize)

				f.write('<td class="light">' + filetext + '</td>')
				f.write('<td class="light">' + str(time.ctime(os.path.getmtime(fullname))) + '</td>')
				
				f.write('<td class="light"><center><button onclick=\"clearKey()\" type=\"submit\" value=\"%s\" formaction=\"%s\" name=\"deletefile\">Delete File</button></center></td>\n' % (urllib.parse.quote(linkname), urllib.parse.quote(linkname)))
				f.write('<td class="light"><a href=\"%s\">%s</a></td>\n' % (urllib.parse.quote(linkname), linkname))
				f.write("</tr>")

			elif form==2:
				f.write('<tr class="light">')
				f.write('<td class="light"><button onclick=\"clearKey()\" class="link" type=\"submit\" value=\"%s\" formmethod=\"get\" formaction=\"%s\">%s</button></td>' % (urllib.parse.quote(linkname),  urllib.parse.quote(linkname), cgi.escape(displayname)))
				
				f.write('<td class="light">&lt;dir&gt;</td>\n')
				f.write('<td class="light">' + str(time.ctime(os.path.getmtime(fullname))) + '</td>')

				try:
					if len(os.listdir(fullname))==0:
						f.write('<td class="light"><center><button onclick=\"clearKey()\" formaction=\"%s\" type=\"submit\" value=\"%s\" name=\"removedir\">Remove Dir</button></center></td>' % (urllib.parse.quote(linkname), displayname))
					else:
						f.write('<td class="light"></td>')
				except:
					f.write('<td class="light"></td>')
		f.write("</table></form>")
		f.write("</ul>\n<hr/>\n")
		f.write("</body>\n</html>\n")
		length = f.tell()
		f.seek(0)
		self.send_response(200)
		self.send_header("Content-type", "text/html")
		cookies=SimpleCookie(self.headers.get('Cookie'))
		username=""
		pauth=cookies.get("p_auth").value
		temp=pauth.split("&")
		for x in temp:
			temp2=x.split("=")
			if temp2[0]=="username":
				username=temp2[1]
				break
		cookie=genCookie(secret_key, username, self.client_address[0])
		self.send_header("Set-cookie", cookie.output(header='', sep=''))

		self.send_header("Content-Length", str(length))
		self.end_headers()
		return f

	def translate_path(self, path):
		"""Translate a /-separated PATH to the local filename syntax.

		Components that mean special things to the local file system
		(e.g. drive or directory names) are ignored.  (XXX They should
		probably be diagnosed.)

		"""
		# abandon query parameters
		path = path.split('?',1)[0]
		path = path.split('#',1)[0]
		path = posixpath.normpath(urllib.parse.unquote(path))
		words = path.split('/')
		words = filter(None, words)
		path = os.getcwd()
		for word in words:
			drive, word = os.path.splitdrive(word)
			head, word = os.path.split(word)
			if word in (os.curdir, os.pardir): continue
			path = os.path.join(path, word)
		return path

	def copyfile(self, source, outputfile):
		if isinstance(source, str):
			outputfile.write(str.encode(source))
		else:
			outputfile.write(source)
		
	def guess_type(self, path):

		base, ext = posixpath.splitext(path)
		if ext in self.extensions_map:
			return self.extensions_map[ext]
		ext = ext.lower()
		if ext in self.extensions_map:
			return self.extensions_map[ext]
		else:
			return self.extensions_map['']

	if not mimetypes.inited:
		mimetypes.init() # try to read system mime.types
	extensions_map = mimetypes.types_map.copy()
	extensions_map.update({
		'': 'application/octet-stream', # Default
		'.py': 'text/plain',
		'.c': 'text/plain',
		'.h': 'text/plain',
		'.jpg': 'image/jpeg'
		})


def run(tcpport=8000, address=''):

	try:
		server_address = (address, tcpport)
		httpd = ThreadingSimpleServer(server_address, MainProcess)
		httpd.timeout = 60
		httpd.serve_forever()
	except Exception:
		print("Exception in Main", Exception)
		exit(1)

if __name__ == '__main__':
	parser=argparse.ArgumentParser()
	parser.add_argument('--port', nargs='?', help='TCP Port')
	parser.add_argument('--listen', nargs='?', help='Listen Address')
	parser.add_argument('--path', nargs='?', help='Listen Address')
	parser.add_argument('--secretkey', nargs='?', help='Hard Code Secret Key Instead; Default is Randomly Generate')
	parser.add_argument('--banner', nargs='?', help='Banner')
	parser.add_argument('--secure', action='store_true', help='Require Cookie to Be Sent Securely')
	parser.add_argument('--group', nargs='?', help='Authorized Group')
	parser.add_argument('--disablepam', action='store_true', help='Disable Authentication')
	parser.add_argument('--noip', action='store_true', help='Disables Checking the IP Address as Part of Authentication')

	args = parser.parse_args()
	port=8000
	listen=''
	if args.port:
		try:
			port=int(args.port)
			if not (port>0 and port<65536):
				print("--port must be between 0 and 65536")
				exit(1)
		except:
			print("--port is not an integer")
			exit(1)


	if args.path:
		workingpath=args.path
	else:
		workingpath=os.getcwd()

	if args.listen:
		listen=args.listen
	global secret_key
	if not args.secretkey:
		secret_key = randomString().encode()
	else:
		secret_key=args.secretkey.encode()
	global pamenabled
	if args.disablepam:
		pamenabled=False
	else:
		pamenabled=True
	global banner
	if args.banner:
		banner=args.banner
	else:
		banner="/etc/issue"

	global cookiesecure
	if args.secure:
		cookiesecure=True
	else:
		cookiesecure=False

	global authorizedGroup
	if args.group:
		authorizedGroup=args.group
	else:
		authorizedGroup=""
	global checkip
	if args.noip:
		checkip=False
	else:
		checkip=True
	
	run(tcpport=port, address=listen)
	exit(0)
