#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket, threading, sys, getopt, re, time, thread, os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from random import randint


#constants for Diffie-Hellman
p = 45215679089341564880983468793221
g = 2

class ClientThread(threading.Thread):

	#function constructor
	def __init__(self,ip,port,socket):
		threading.Thread.__init__(self)
		self.ip = ip
		self.port = port
		self.socket = socket
		print "[+] New thread started for "+ip+":"+str(port)

	#RSA decryption
	def decode(self,encryptedtext):
		try:
			serverkey='server'
			global private_key_server
			with open("%s" % serverkey, "rb") as key_file:
				private_key_server=serialization.load_pem_private_key(key_file.read(),password=None,backend=default_backend())
				plaintext = private_key_server.decrypt(encryptedtext,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
				return plaintext
		except ValueError:
			print "Closing connection from : "+ip+":"+str(port) 
			thread.exit()

	#RSA signing
	def sign(self,msg):
		signer = private_key_server.signer(padding.PSS(mgf=padding.MGF1(hashes.SHA1()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA1())
		signer.update(msg)
		signed_message = signer.finalize()
		return signed_message

	#logging in user
	def run(self):
		global onlineusers   
		print "Connection from : "+ip+":"+str(port)
		data = "dummydata"

		while 1:
			data = self.socket.recv(2048)
			data = ClientThread.decode(self,data)
			rnd1=randint(10000,100000)
			rnd2=randint(10000,100000)
			reply=str(rnd1)+'&&&'+str(rnd2)
			reply= reply+'&&&'+ClientThread.sign(self,reply)
			self.socket.send(reply)
			data = self.socket.recv(2048)
			data = ClientThread.decode(self,data)

			#checking challenge response
			if int(data)==rnd1*rnd2:
				reply='sucess'
				print reply
				reply= reply+'&&&'+ClientThread.sign(self,reply)
				self.socket.send(reply)
				break

			else:
				reply="Challenge Response failed"
				print reply
				reply= reply+'&&&'+ClientThread.sign(self,reply)
				self.socket.send(reply)
				continue
		
		#connecting client
		while 1: 
			data = self.socket.recv(2048)
			data = ClientThread.decode(self,data)
			
			#Connect+User+Timestamp
			if 'connect' in data:
				m =  re.search('(?<=connect)\w+',data)
				m1 = re.search('(?<=&&&)\w+',data)
				if  m.group(0) in users and m.group(0) not in onlineusers:
					ClientThread.checkReplay(self,m1.group(0),m.group(0))
					status,key=ClientThread.checkUser(self,m.group(0))
					if status=="authentication failed":
						continue
					elif status=='sucess':
						break
				else:
					ClientThread.timeNow(self)
					reply="You are not a registered user or already logged in "+'&&&'+str(ts)
					reply= reply+'&&&'+ClientThread.sign(self,reply)
					self.socket.send(reply)

		ClientThread.userfunctions(self,m.group(0),key)

	# gives the current time in seconds since epoc
	# Returns: None
	def timeNow(self) :
		global ts
		ts = time.time()

	# checks for replay by checking if the timestamp is older than 5 seconds
	# Returns: None
	def checkReplay(self,timestamp,user):
		ClientThread.timeNow(self)
		if (int(timestamp)+5) > ts:
			pass
		else :
			print "replay from" + " " + user

	# checks if the user is a legitimate user 
	# Returns: String
	def checkUser(self,user):
		global onlineusers
		ClientThread.timeNow(self)
		global loginattempts

		#sending Salt Time
		reply = str(users[users.index(user)+2]) + '&&&' + str(ts)
		reply = reply+'&&&'+ClientThread.sign(self,reply)
		self.socket.send(reply)

		#Receiving User+Passsalt+time+dhkey
		data = self.socket.recv(4096)
		data = ClientThread.decode(self,data)
		m =  re.split(r'&&&',data)
		m[2]=int(float(m[2]))
		ClientThread.checkReplay(self,str(m[2]),user)

		#checking for number of invalid password attempts
		try:
			a=loginattempts.index(user)
		except ValueError:
			loginattempts.extend((user,0))
		a=loginattempts.index(user)
		if m[1] == users[users.index(user)+1] and loginattempts[a+1]<5:
			print "user "+ user + " logged in"
			randnum=randint(1,100)
			l1=[user,randnum]
			dhclientkey = g**randnum % p
			
			#global symkey
			symkey=(int(m[3]))**randnum %p
			self.socket.send('welcome '+ user)
			key1=ClientThread.generatesymkey(self,symkey)
			onlineusers.extend((user,str(self.ip),str(self.port),m[4],key1))
			ClientThread.timeNow(self)
			data = self.socket.recv(4096)

			#sending dhclientkey
			reply= str(dhclientkey)+'&&&'+str(ts)
			reply= reply+'&&&'+ClientThread.sign(self,reply)
			self.socket.send(reply)
			return ("sucess",symkey)
		
		#if user exceeds number of attempts allowed
		else:
			b=loginattempts[a+1]
			loginattempts[a+1]=b+1
			print "invalid password from " +user

			if loginattempts[a+1]>=5:
				if loginattempts[a+1]==5:
					thread.start_new_thread(ClientThread.waitforamin,(self,a, ))
				reply = str("Invalid password entered 5 times. Wait 1 minute before entering again ")
			else:
				reply = str("Invalid password. Please re-enter your password ")
			self.socket.send(reply)
			return ("authentication failed","nokey")

	# counter for 1 minute wait if user enters wrong password 5 times
	# Returns: None
	def waitforamin(self,a):
		global loginattempts
		t_end = time.time() + 60
		while time.time() < t_end:
			o=1
		loginattempts[a+1]=0

	# generates a new symmetric key by using SHA2 hashing
	# Returns: None
	def generatesymkey(self,key):
		digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
		digest.update(str.encode(str(key)))
		ssu=digest.finalize()
		return ssu
	   
	# decrypts given message using given key sent by given user. Algorithm is AES
	# Returns: String     
	def symdecryption(self,msg,key1,user):
		global onlineusers
		try:
			backend = default_backend()
			iv=msg[-16:]
			msg=msg[:-16]
			length=int(msg[-2:])
			msg=msg[:-2]
			cipher = Cipher(algorithms.AES(key1), modes.CBC(iv), backend=backend)
			decryptor = cipher.decryptor()
			decoded=decryptor.update(msg) + decryptor.finalize()
			decoded = decoded[:-length]
			return decoded

		except ValueError:
			ind=onlineusers.index(user)
			del onlineusers[ind]
			del onlineusers[ind]
			del onlineusers[ind]
			del onlineusers[ind]
			del onlineusers[ind]
			thread.exit()
	  
	# encrypts a given message using the given key using AES algorithm
	# Returns: String 
	def symencryption(self,msg,key1):
		backend = default_backend()
		iv = os.urandom(16)
		cipher = Cipher(algorithms.AES(key1), modes.CBC(iv), backend=backend)
		encryptor = cipher.encryptor()
		length = 16 - (len(msg) % 16)
		msg = msg+chr(97)*length
		if length<10:
			lent="0"+str(length)
		if length>9:
			lent=str(length)
		symencrypted=encryptor.update(msg) + encryptor.finalize()
		return symencrypted+lent+iv

	# handles requests by cleints
	# Returns: None
	def userfunctions(self,user,key):
		global onlineusers
		key1=ClientThread.generatesymkey(self,key)
		while(1):
			data = self.socket.recv(4096)
			data=ClientThread.symdecryption(self,data,key1,user)
			m =  re.split(r'&&&',data)
			m[1]=int(float(m[1]))
			ClientThread.checkReplay(self,str(m[1]),user)

			#if user asks for list of online users
			if m[0] == "list":
				j=0
				data="Online Users: \n"
				for i in onlineusers:
					if j % 5 ==0 and i !=user:
						data=data + i+'\n'
						j+=1
					else:
						j+=1
						continue
				if data=="":
					data="No user online"
				data=ClientThread.symencryption(self,data,key1)
				self.socket.send(data)

			#if user wants to communicate with another user
			if "send" in m[0]:
				data=re.split(r' ',m[0])

				if len(data) == 2 and data[0] == 'send' and data[1] in onlineusers:
					if data[1] == user:
						data=ClientThread.symencryption(self,"Cannot send message to yourself ",key1)
						self.socket.send(data)
						continue
					ind=onlineusers.index(data[1])
					randnum=randint(1,100)
					ClientThread.timeNow(self)
					
					#key2=ClientThread.generatesymkey(self,randnum)
					data=str(onlineusers[ind+1])+'&&&'+str(onlineusers[ind+3])+'&&&'+str(ts)+'&&&'+data[1]+'&&&'+str(randnum)+'&&&'+ClientThread.symencryption(self,user+'&&&'+str(randnum)+'&&&'+str(ts),onlineusers[ind+4])
					data=ClientThread.symencryption(self,data,key1)
					self.socket.send(data)
				if len(data) == 2 and data[0] == 'send' and data[1] not in onlineusers:
					data = "User does not exist or is offline"
					data=ClientThread.symencryption(self,data,key1)
					self.socket.send(data)
					
# main function
if __name__ == "__main__":
	host = "localhost"
	port = 8888
	if(len(sys.argv) < 3) :
		print 'Usage : python tcpclient.py SERVER-IP SERVER-PORT'
		sys.exit()
	host = sys.argv[1]
	port = int(sys.argv[2])
	CONNECTION_LIST = []
	loginattempts=[]
	onlineusers=[]

	#pre registered list of users
	users = ['sam', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', '456', 'tom', '36e57e7769b552c64f583691acf28b747f2429652748b0d71658f45514d871f4', '101112','ninja','4ad7724b7143b7427fa364d4e00dc8ca3cddf629941dce9a0f413e35f6baa397','1011']

	#creating TCP sockets
	tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	try:
		tcpsock.bind((host,port))
	except socket.error as err:
		print "Could not start server. Error: " +str(err)
		sys.exit(0)
	threads = []

	#listening for incoming connections
	while True:
		tcpsock.listen(4)
		print "\nListening for incoming connections..."
		(clientsock, (ip, port)) = tcpsock.accept()
		newthread = ClientThread(ip, port, clientsock)
		newthread.start()
		threads.append(newthread)

	#handling client threads
	for t in threads:
		t.join()
