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
from _thread import *
import threading
from time import sleep
import sys
import fcntl
import traceback
import select
import ssl


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


def genCookie(secret_key, username, ipaddress, invalid=False):
	global cookiesecure
	#expiration=str(datetime.datetime.now()+datetime.timedelta(minutes=60))
	expiration=str(datetime.datetime.now()+datetime.timedelta(minutes=60))
	params="username="+username + "&expiration=" + expiration + "&ipaddress=" + str(ipaddress)
	salt=randomString(stringLength=16)
	# Username is a pepper, salt is random salt and secret_key is global
	if ipaddress==None:
		ipaddress="127.0.0.1"
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
	if clientip==None:
		clientip="127.0.0.1"
	try:
		print(cookie)
		temp=cookie
		try:
			cookie=temp.split("&sig=")[0]
			sig1=temp.split("&sig=")[1]
			salt=sig1[0:16]		
		except:
			return False
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
		return True
	except Exception:
		print("Invalid Cookie", sys.exc_info())
		#print("Invalid Cookie", logger.error(str(Exception), exc_info=True))
		return False

def refreshCookie(secret_key, cookie, clientip):
	print("In Validate Cookie")

	try:
		print(cookie)
		temp=cookie
		try:
			cookie=temp.split("&sig=")[0]
			sig1=temp.split("&sig=")[1]
			salt=sig1[0:16]		
		except:
			return False
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
				elif currentdate>(expirationdate-datetime.timedelta(hours=0, minutes=55)):
					return True
		return False				
	except Exception:
		print("Invalid Cookie", sys.exc_info())
		#print("Invalid Cookie", logger.error(str(Exception), exc_info=True))
		return False



def sha2_hash(hash_string):
	return hashlib.sha256(hash_string.encode())

class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    pass

class MainProcess(BaseHTTPServer.BaseHTTPRequestHandler):
	timeout=.03

	def dataConnector(self, initial_data, hostname, hostport):
		print("In dataConnector")
		try:
			main_socket=self.connection
			fcntl.fcntl(main_socket, fcntl.F_SETFL, os.O_NONBLOCK)
			secondary_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			secondary_socket.connect((hostname, hostport))
			fcntl.fcntl(secondary_socket, fcntl.F_SETFL, os.O_NONBLOCK)
			secondary_socket.settimeout(.5)
			#secondary_socket.settimeout(10)
			secondary_socket.sendall(initial_data.encode())
			temp="Data"
			while not temp==b'':
				try:
					temp=main_socket.recv(8192)
					if(not temp==b''):
						secondary_socket.sendall(temp)

				except Exception:
					#print("Timeout Error 1")
					break

			while not temp==b'':
				#print(counter)
				try:
					temp=secondary_socket.recv(8192)
					if(not temp==b''):
						main_socket.sendall(temp)

				except Exception:
					#print("Timeout Error 2")
					break
				#print("Main:" + str(main_socket.fileno()))
				if main_socket.fileno()==-1:
					print("Exiting Because main socket closed")
					break
				#print("Secondary:" + str(main_socket.fileno()))
				if secondary_socket.fileno()==-1:
					print("Exiting Because secondary socket closed")
					break
			print("Exiting Connector")
		except Exception:
			self.handle_connection_error()
		
	def dataConnectorCONNECT(self, length, initial_data, hostname, hostport):
		try:
			print("In dataConnector Post")
			main_socket=self.connection
			fcntl.fcntl(main_socket, fcntl.F_SETFL, os.O_NONBLOCK)
			secondary_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			secondary_socket.connect((hostname, hostport))
			fcntl.fcntl(secondary_socket, fcntl.F_SETFL, os.O_NONBLOCK)
			secondary_socket.settimeout(.03)
			secondary_socket.sendall(initial_data.encode())
			temp=self.rfile.read(length)
			secondary_socket.sendall(temp)
			counter=0
			while counter<40:
				try:
					temp=main_socket.recv(8192)
					if(temp==b''):
						counter+=1
					else:
						secondary_socket.sendall(temp)
						counter=0

				except Exception:
					counter+=1
					pass
				try:
					temp=secondary_socket.recv(8192)
					if(temp==b''):
						counter+=1
					else:
						main_socket.sendall(temp)
						counter=0
				except Exception:
					counter+=1
					pass
				if main_socket.fileno()==-1:
					#print("Exiting Because main socket closed")
					break
				if secondary_socket.fileno()==-1:
					#print("Exiting Because secondary socket closed")
					break
				if counter==40:
					if secondary_socket.fileno()==0:
						counter=0
			main_socket.close()
			secondary_socket.close()
		except Exception:
			self.handle_connection_error()



	def dataConnectorPOST(self, length, initial_data, hostname, hostport):
		try:
			print("In dataConnector Post")
			main_socket=self.connection
			fcntl.fcntl(main_socket, fcntl.F_SETFL, os.O_NONBLOCK)
			secondary_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			secondary_socket.connect((hostname, hostport))
			fcntl.fcntl(secondary_socket, fcntl.F_SETFL, os.O_NONBLOCK)
			secondary_socket.settimeout(.5)
			secondary_socket.sendall(initial_data.encode())
			temp=self.rfile.read(length)
			secondary_socket.sendall(temp)
			counter=0
			temp="Data"
			while not temp==b'':
				try:
					temp=main_socket.recv(8192)
					if(not temp==b''):
						secondary_socket.sendall(temp)
					
				except Exception:
					break
			while not temp==b'':
				try:
					temp=secondary_socket.recv(8192)
					if(not temp==b''):
						main_socket.sendall(temp)
				except Exception:
					break
				if main_socket.fileno()==-1:
					#print("Exiting Because main socket closed")
					break
				if secondary_socket.fileno()==-1:
					#print("Exiting Because secondary socket closed")
					break
			#print("Exiting Connector Post")
		except Exception:
			self.handle_connection_error()

	def do_PATCH(self):
		print("In do_PATCH")
		global secret_key
		global pamenabled
		global remotehost
		global remoteport
		cookies=SimpleCookie(self.headers.get('Cookie'))

		path=self.path

		if pamenabled==True:
			try:
				cookie=cookies.get("p_auth").value
				clientip=self.client_address[0]
				if clientip=="127.0.0.1":
					if not self.headers.get("x-forwarded-for")=="":
						clientip=self.headers.get("x-forwarded-for")			

				result=validateCookie(secret_key, cookie, clientip)
			except:
				result=False

			if result==False:
				if self.path==("/authentication_services"):
					self.handle_auth()
					return None
				else:
					self.send_response(301)
					self.send_header("Location", "/authentication_services")
					self.end_headers()
					return None
			else:
				result=refreshCookie(secret_key, cookie, self.client_address[0])
				if result==True:
					print("Refreshing Cookie")
					cookie=cookies.get("p_auth").value
					data=cookie.split("username=")[1]
					username=data.split("&")[0]
					clientip=self.client_address[0]
					if clientip=="127.0.0.1":
						if not self.headers.get("x-forwarded-for")=="":
							clientip=self.headers.get("x-forwarded-for")			

					cookie=genCookie(secret_key, username, clientip)
					self.send_response(301)
					self.send_header("Set-cookie", cookie.output(header='', sep=''))
					self.send_header("Location", self.path)
					print(self.path)
					self.end_headers()
					print(cookie.output)
					return None
					
		
			cookie=cookies.get("p_auth").value
			data=cookie.split("username=")[1]
			username=data.split("&")[0]
		else:
			username="guest"
		
		temp="PATCH " + self.path + " " + "HTTP/1.1\r\n"
		for x in self.headers:
			if x.lower()=="remote_user":
				print("Skipping " + x.lower())
			elif x.lower()=="cookie":
				cookietemp=self.headers.get(x).split("=")[0]
				if cookietemp.lower()=="p_auth":
					print("Skipping " + x.lower())
				else:
					temp=temp+x+": " + self.headers.get(x) + "\r\n"
			else:
				temp=temp+x+": " + self.headers.get(x) + "\r\n"
		temp=temp+"remote_user: " + username + "\r\n\r\n"
		#print(temp)
		length = int(self.headers['content-length'])
		self.dataConnectorPOST(length, temp, remotehost, int(remoteport))



	# Put Method Unsupported; probably need to add an error message at some point.
	def do_PUT(self):
		print("In do_PUT")
		global secret_key
		global pamenabled
		global remotehost
		global remoteport
		cookies=SimpleCookie(self.headers.get('Cookie'))

		path=self.path

		if pamenabled==True:
			try:
				cookie=cookies.get("p_auth").value
				clientip=self.client_address[0]
				if clientip=="127.0.0.1":
					if not self.headers.get("x-forwarded-for")=="":
						clientip=self.headers.get("x-forwarded-for")			

				result=validateCookie(secret_key, cookie, clientip)
			except:
				result=False

			if result==False:
				if self.path==("/authentication_services"):
					self.handle_auth()
					return None
				else:
					self.send_response(302)
					self.send_header("Location", "/authentication_services")
					self.end_headers()
					return None
			else:
				result=refreshCookie(secret_key, cookie, self.client_address[0])
				if result==True:
					print("Refreshing Cookie")
					cookie=cookies.get("p_auth").value
					data=cookie.split("username=")[1]
					username=data.split("&")[0]
					clientip=self.client_address[0]
					if clientip=="127.0.0.1":
						if not self.headers.get("x-forwarded-for")=="":
							clientip=self.headers.get("x-forwarded-for")			

					cookie=genCookie(secret_key, username, clientip)
					self.send_response(302)
					self.send_header("Set-cookie", cookie.output(header='', sep=''))
					self.send_header("Location", self.path)
					print(self.path)
					self.end_headers()
					print(cookie.output)
					return None
					
		
			cookie=cookies.get("p_auth").value
			data=cookie.split("username=")[1]
			username=data.split("&")[0]
		else:
			username="guest"
		
		temp="PUT " + self.path + " " + "HTTP/1.1\r\n"
		for x in self.headers:
			if x.lower()=="remote_user":
				print("Skipping " + x.lower())
			elif x.lower()=="cookie":
				cookietemp=self.headers.get(x).split("=")[0]
				if cookietemp.lower()=="p_auth":
					print("Skipping " + x.lower())
				else:
					temp=temp+x+": " + self.headers.get(x) + "\r\n"
			else:
				temp=temp+x+": " + self.headers.get(x) + "\r\n"
		temp=temp+"remote_user: " + username + "\r\n\r\n"
		#print(temp)
		length = int(self.headers['content-length'])
		self.dataConnectorPOST(length, temp, remotehost, int(remoteport))



	def do_GET(self):
		print("In do_GET")
		global secret_key
		global pamenabled
		global remotehost
		global remoteport
		cookies=SimpleCookie(self.headers.get('Cookie'))

		path=self.path

		if pamenabled==True:
			try:
				cookie=cookies.get("p_auth").value
				clientip=self.client_address[0]
				if clientip=="127.0.0.1":
					if not self.headers.get("x-forwarded-for")=="":
						clientip=self.headers.get("x-forwarded-for")			

				result=validateCookie(secret_key, cookie, clientip)
			except:
				result=False

			if result==False:
				if self.path==("/authentication_services"):
					self.handle_auth()
					return None
				elif self.path==("/authentication_error"):
					self.handle_auth_error()
					return None
				else:
					self.send_response(302)
					self.send_header("Location", "/authentication_services")
					self.end_headers()
					return None
			else:
				result=refreshCookie(secret_key, cookie, self.client_address[0])
				if result==True:
					print("Refreshing Cookie")
					cookie=cookies.get("p_auth").value
					data=cookie.split("username=")[1]
					username=data.split("&")[0]
					clientip=self.client_address[0]
					if clientip=="127.0.0.1":
						if not self.headers.get("x-forwarded-for")=="":
							clientip=self.headers.get("x-forwarded-for")			

					cookie=genCookie(secret_key, username, clientip)
					self.send_response(302)
					self.send_header("Set-cookie", cookie.output(header='', sep=''))
					self.send_header("Location", self.path)
					print(self.path)
					self.end_headers()
					print(cookie.output)
					return None
					
		
			cookie=cookies.get("p_auth").value
			data=cookie.split("username=")[1]
			username=data.split("&")[0]
		else:
			username="guest"
		
		upgraderequested=False
		websocketrequested=False
		temp="GET " + self.path + " " + "HTTP/1.1\r\n"
		for x in self.headers:
			if x.lower()=="remote_user":
				print("Skipping " + x.lower())
			elif x.lower()=="cookie":
				cookietemp=self.headers.get(x).split("=")[0]
				if cookietemp.lower()=="p_auth":
					print("Skipping " + x.lower() + " because it matches " + cookietemp.lower())
				else:
					temp=temp+x+": " + self.headers.get(x) + "\r\n"
			elif x.lower()=="connection" and self.headers.get(x).lower()=="upgrade":
				upgraderequested=True
				temp=temp+x+": " + self.headers.get(x) + "\r\n"
			elif x.lower()=="upgrade" and self.headers.get(x).lower()=="websocket":
				websocketrequested=True
				temp=temp+x+": " + self.headers.get(x) + "\r\n"
			else:
				temp=temp+x+": " + self.headers.get(x) + "\r\n"
		temp=temp+"remote_user: " + username + "\r\n\r\n"
		#print(temp)
		if upgraderequested==True and websocketrequested==True:
			print("--------------------------------------\nSocket Upgrade Requested to Websocket\n---------------------------------")
			self.dataConnectorCONNECT(0, temp, remotehost, int(remoteport))
		else:	
			self.dataConnector(temp, remotehost, int(remoteport))


	def do_DELETE(self):
		print("In do_DELETE")
		global secret_key
		global pamenabled
		global remotehost
		global remoteport
		cookies=SimpleCookie(self.headers.get('Cookie'))

		path=self.path

		if pamenabled==True:
			try:
				cookie=cookies.get("p_auth").value
				clientip=self.client_address[0]
				if clientip=="127.0.0.1":
					if not self.headers.get("x-forwarded-for")=="":
						clientip=self.headers.get("x-forwarded-for")			

				result=validateCookie(secret_key, cookie, clientip)
			except:
				result=False

			if result==False:
				if self.path==("/authentication_services"):
					self.handle_auth()
					return None
				else:
					self.send_response(302)
					self.send_header("Location", "/authentication_services")
					self.end_headers()
					return None
			else:
				result=refreshCookie(secret_key, cookie, self.client_address[0])
				if result==True:
					print("Refreshing Cookie")
					cookie=cookies.get("p_auth").value
					data=cookie.split("username=")[1]
					username=data.split("&")[0]
					clientip=self.client_address[0]
					if clientip=="127.0.0.1":
						if not self.headers.get("x-forwarded-for")=="":
							clientip=self.headers.get("x-forwarded-for")			

					cookie=genCookie(secret_key, username, clientip)
					self.send_response(302)
					self.send_header("Set-cookie", cookie.output(header='', sep=''))
					self.send_header("Location", self.path)
					print(self.path)
					self.end_headers()
					print(cookie.output)
					return None
					
		
			cookie=cookies.get("p_auth").value
			data=cookie.split("username=")[1]
			username=data.split("&")[0]
		else:
			username="guest"
		
		temp="DELETE " + self.path + " " + "HTTP/1.1\r\n"
		for x in self.headers:
			if x.lower()=="remote_user":
				print("Skipping " + x.lower())
			elif x.lower()=="cookie":
				cookietemp=self.headers.get(x).split("=")[0]
				if cookietemp.lower()=="p_auth":
					print("Skipping " + x.lower())
				else:
					temp=temp+x+": " + self.headers.get(x) + "\r\n"
			else:
				temp=temp+x+": " + self.headers.get(x) + "\r\n"
		temp=temp+"remote_user: " + username + "\r\n\r\n"
		#print(temp)
		self.dataConnector(temp, remotehost, int(remoteport))



	def do_HEAD(self):
		print("In do_HEAD")
		global secret_key
		global pamenabled
		global remotehost
		global remoteport
		cookies=SimpleCookie(self.headers.get('Cookie'))

		path=self.path

		if pamenabled==True:
			try:
				cookie=cookies.get("p_auth").value
				clientip=self.client_address[0]
				if clientip=="127.0.0.1":
					if not self.headers.get("x-forwarded-for")=="":
						clientip=self.headers.get("x-forwarded-for")			

				result=validateCookie(secret_key, cookie, clientip)
			except:
				result=False

			if result==False:
				if self.path==("/authentication_services"):
					self.handle_auth()
					return None
				else:
					self.send_response(302)
					self.send_header("Location", "/authentication_services")
					self.end_headers()
					return None
			else:
				result=refreshCookie(secret_key, cookie, self.client_address[0])
				if result==True:
					print("Refreshing Cookie")
					cookie=cookies.get("p_auth").value
					data=cookie.split("username=")[1]
					username=data.split("&")[0]
					clientip=self.client_address[0]
					if clientip=="127.0.0.1":
						if not self.headers.get("x-forwarded-for")=="":
							clientip=self.headers.get("x-forwarded-for")			

					cookie=genCookie(secret_key, username, clientip)
					self.send_response(302)
					self.send_header("Set-cookie", cookie.output(header='', sep=''))
					self.send_header("Location", self.path)
					print(self.path)
					self.end_headers()
					print(cookie.output)
					return None
					
		
			cookie=cookies.get("p_auth").value
			data=cookie.split("username=")[1]
			username=data.split("&")[0]
		else:
			username="guest"
		
		temp="HEAD " + self.path + " " + "HTTP/1.1\r\n"
		for x in self.headers:
			if x.lower()=="remote_user":
				print("Skipping " + x.lower())
			elif x.lower()=="cookie":
				cookietemp=self.headers.get(x).split("=")[0]
				if cookietemp.lower()=="p_auth":
					print("Skipping " + x.lower())
				else:
					temp=temp+x+": " + self.headers.get(x) + "\r\n"
			else:
				temp=temp+x+": " + self.headers.get(x) + "\r\n"
		temp=temp+"remote_user: " + username + "\r\n\r\n"
		#print(temp)		
		self.dataConnector(temp, remotehost, int(remoteport))

		
		

	def do_POST(self):
		print("In do_POST")

		global secret_key
		global pamenabled
		global pamservice
		cookies=SimpleCookie(self.headers.get('Cookie'))
		path=self.path
		if pamenabled==True:
			try:
				cookie=cookies.get("p_auth").value
				clientip=self.client_address[0]
				if clientip=="127.0.0.1":
					if not self.headers.get("x-forwarded-for")=="":
						clientip=self.headers.get("x-forwarded-for")			

				result=validateCookie(secret_key, cookie, clientip)
			except:
				result=False

			if result==False:
				if self.path=="/authentication_services" and 'multipart/form-data' in self.headers['Content-Type'].lower():
					temp=self.headers['Content-Type'].replace("form-data", "mixed")
					data="MIME-Version: 1.0\nContent-Type: " + temp + "\n\nDummyData\n"
					length = int(self.headers['content-length'])
					temp=self.rfile.read(length)
					data=data+temp.decode("cp437")

					try:
						msg=email.message_from_string(data)
					except Exception as e:
						print("Exception Decoding Mime Message")
						return(False, "Error Decodong Message")
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
						print("Exception in Authorization", sys.exc_info())
						pass
					
					
					#groups=[g.gr_name for g in grp.getgrall() if username in g.gr_mem]
					'''gid=pwd.getpwnam(username).pw_gid
					groups.append(grp.getgrgid(gid).gr_name)
					print(groups)'''
					#print(groups)


					isAuthenticated=p.authenticate(username, password, service=pamservice)
					print("User ", username, " is authenticated ", str(isAuthenticated))
					if isAuthenticated and isAuthorized:
						clientip=self.client_address[0]
						if clientip=="127.0.0.1":
							if not self.headers.get("x-forwarded-for")=="":
								clientip=self.headers.get("x-forwarded-for")			

						cookie=genCookie(secret_key, username, clientip)
						self.send_response(302)
						print(cookie)
						self.send_header("Set-cookie", cookie.output(header='', sep=''))
						#self.send_header("Location", "/")
						if cookies.get("p_ref")==None:
							self.send_header("Location", "/")
						else:
							try:
								cookie=cookies.get("p_ref").value
								if cookie=="/authentication_services":
									self.send_header("Location", "/")
								else:			
									self.send_header("Location", cookie)
							except:
								self.send_header("Location", "/")
						self.end_headers()
					else:
						self.send_response(302)
						self.send_header("Location", "/authentication_error")
						self.end_headers()
						return("Unauthenticated", "Authentication Failure")
			else:
				self.checkAuth(secret_key, cookies)
				result=refreshCookie(secret_key, cookie, self.client_address[0])
				if result==True:
					print("Refreshing Cookie")
					cookie=cookies.get("p_auth").value
					data=cookie.split("username=")[1]
					username=data.split("&")[0]
					clientip=self.client_address[0]
					if clientip=="127.0.0.1":
						if not self.headers.get("x-forwarded-for")=="":
							clientip=self.headers.get("x-forwarded-for")			

					cookie=genCookie(secret_key, username, clientip)
					self.send_response(302)
					self.send_header("Set-cookie", cookie.output(header='', sep=''))
					self.send_header("Location", self.path)
					print(self.path)
					self.end_headers()
					print(cookie.output)
					return None


		if pamenabled==True:
			try:
				cookie=cookies.get("p_auth").value
				data=cookie.split("username=")[1]
				username=data.split("&")[0]
			except:
				username="guest"
		else:
			username="guest"
		
		temp="POST " + self.path + " " + "HTTP/1.1\r\n"

		for x in self.headers:
			if x.lower()=="remote_user":
				print("Skipping " + x.lower())
			elif x.lower()=="cookie":
				cookietemp=self.headers.get(x).split("=")[0]
				if cookietemp.lower()=="p_auth":
					print("Skipping " + x.lower())
				else:
					temp=temp+x+": " + self.headers.get(x) + "\r\n"
			else:
				temp=temp+x+": " + self.headers.get(x) + "\r\n"
		temp=temp+"remote_user: " + username + "\r\n\r\n"
		length = int(self.headers['content-length'])
		self.dataConnectorPOST(length, temp, remotehost, int(remoteport))

	def do_CONNECT(self, initial_data):
		print("In do_Connect")
		global secret_key
		global pamenabled
		cookies=SimpleCookie(self.headers.get('Cookie'))

		path=self.path

		if pamenabled==True:
			try:
				cookie=cookies.get("p_auth").value
				clientip=self.client_address[0]
				if clientip=="127.0.0.1":
					if not self.headers.get("x-forwarded-for")=="":
						clientip=self.headers.get("x-forwarded-for")			

				result=validateCookie(secret_key, cookie, clientip)
			except:
				result=False

			if result==False:
				self.send_response(302)
				self.send_header("Location", "/authentication_services")
				self.end_headers()
				return None

			temp="CONNECT " + self.path + " " + "HTTP/1.1\r\n"
			cookie=cookies.get("p_auth").value
			data=cookie.split("username=")[1]
			username=data.split("&")[0]
		else:
			username="guest"
		
		for x in self.headers:
			if x.lower()=="remote_user":
				print("Skipping " + x.lower())
			elif x.lower()=="cookie":
				cookietemp=self.headers.get(x).split("=")[0]
				if cookietemp.lower()=="p_auth":
					print("Skipping " + x.lower())
				else:
					temp=temp+x+": " + self.headers.get(x) + "\r\n"
			else:
				temp=temp+x+": " + self.headers.get(x) + "\r\n"
		temp=temp+"remote_user: " + username + "\r\n\r\n"
		#print(temp)

		self.dataConnectorCONNECT(0, temp, remotehost, int(remoteport))

	def checkAuth(self, secret_key, cookies):
		try:
			print("In Check Auth")
			try:
				cookie=cookies.get("p_auth").value
				clientip=self.client_address[0]
				if clientip=="127.0.0.1":
					if not self.headers.get("x-forwarded-for")=="":
						clientip=self.headers.get("x-forwarded-for")			

				result=validateCookie(secret_key, cookie, clientip)
			except:
				result=False
			if result==False:
				print("Redirecting because Cookie isn't valid")
				self.send_response(302)
				self.send_header("Location", "/authentication_services")
				self.end_headers()
				return False
		except Exception:
			print(Exception)
		return True

	def handle_connection_error(self):
		print("In Handle_Connection_Error")
		f = StringIO()
		f.write('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
		f.write("<html lang=\"en\">\n<meta charset=\"utf-8\"/>\n<title>Connection Error</title>\n")
		f.write("<body>\n<h2>Connection Error ... Remote Connection Timed Out or Errored Out</h2>\n")
		f.write("</body></html>")
		self.send_response(500)
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


	def handle_auth_error(self):
		print("In Handle Auth")
		f = StringIO()
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



	def handle_auth(self):
		global banner
		global passwordText
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
		f.write("""<td><b>""")
		#passwordText="Password"
		f.write(passwordText+""":  </b></td><td><input type="password" name="password" autocomplete="none" id="password-input" readonly onfocus="this.removeAttribute('readonly');"/></td>\n""")
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

	def copyfile(self, source, outputfile):
		if isinstance(source, str):
			outputfile.write(str.encode(source))
		else:
			outputfile.write(source)

	

def run(tcpport=8000, address='', cert=''):

	try:
		server_address = (address, tcpport)
		httpd = ThreadingSimpleServer(server_address, MainProcess)
		if not cert=='':
			httpd.socket = ssl.wrap_socket (httpd.socket, certfile=args.cert, server_side=True)

		httpd.timeout = 60
		httpd.serve_forever()
	except Exception:
		print("Exception in Main", sys.exc_info())
		sys.exit(1)

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
	parser.add_argument('--remotehost', nargs='?', help='Remote Host')
	parser.add_argument('--remoteport', nargs='?', help='Remote Port') 	
	parser.add_argument('--pamservice', nargs='?', help='PAM Service (defaults to login)') 	
	parser.add_argument('--cert', nargs='?', help='SSL Cert')
	parser.add_argument('--passwordtext', nargs='?', help='Plaintext Password (if clustering or debugging)')

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
			sys.exit(1)


	if args.path:
		workingpath=args.path
	else:
		workingpath=os.getcwd()

	if args.listen:
		listen=args.listen
	global secret_key
	if not args.secretkey:
		print("Generating Random Secret Key")
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
	global remotehost
	if args.remotehost:
		remotehost=args.remotehost
	else:
		print("--remotehost is required")
		sys.exit(1)

	global remoteport
	if args.remoteport:
		remoteport=args.remoteport
	else:
		print("--remoteport is required")
		sys.exit(1)

	global passwordText
	if args.passwordtext:
		passwordText=args.passwordtext
	else:
		passwordText="Password"


	global pamservice
	if args.pamservice:
		pamservice=args.pamservice
	else:
		pamservice="login"
	if args.cert:
		run(tcpport=port, address=listen, cert=args.cert)
	else:
		run(tcpport=port, address=listen)
	
	exit(0)
