
# Copyright (c) 2008, Diego Aguirre
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright notice,
#       this list of conditions and the following disclaimer in the documentation
#       and/or other materials provided with the distribution.
#     * Neither the name of the DagMoller nor the names of its contributors
#       may be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.

import re
import time
import logging

from twisted.protocols import basic
from twisted.internet import reactor, protocol, task

import distutils.sysconfig
PYTHON_VERSION = distutils.sysconfig.get_python_version()

## Basic Logger
log = logging.getLogger("AsteriskManager")

##
## AsteriskManagerProtocol
##
class AsteriskManagerProtocol(basic.LineOnlyReceiver):
	
	pingInterval = 60
	pingCount    = 0
	pingLimit    = 2
	pingTime     = 0
	
	messageBuffer = {}
	
	server   = None
	hostname = None
	port     = None
	username = None
	password = None
	
	isConnected     = False
	isAuthenticated = False
	
	amiVersion = None
	
	def __init__(self):
		self._taskPing = task.LoopingCall(self.taskPing)
	
	def connectionMade(self):
		peer          = self.transport.getPeer()
		self.hostname = peer.host
		self.port     = peer.port
		
		connector     = self.transport.connector
		self.server   = connector.servername
		self.username = connector.username
		self.password = connector.password
		
		self.messageBuffer[self.server] = []
		
		log.debug("AsteriskManagerProtocol.connectionMade (Server: %s) :: Connection Established to %s:%s..." % (self.server, self.hostname, self.port))
		
		self.factory.servers[self.server]['protocol'] = self
		self.isConnected = True
		
		self.login()
		self._taskPing.start(self.pingInterval, False)
	
	def connectionLost(self, reason):
		self.factory.servers[self.server]['protocol'] = None
		self.isConnected     = False
		self.isAuthenticated = False
		self._taskPing.stop()
		
	def close(self):
		self.transport.loseConnection()
	
	def taskPing(self):
		if self.pingCount == self.pingLimit:
			log.warning("AsteriskManagerProtocol.taskPing (Server: %s) :: PING Timeout after %d seconds..." % (self.server, self.pingCount * self.pingInterval))
			self.pingCount = 0
			self.transport.loseConnection()
		else:
			log.debug("AsteriskManagerProtocol.taskPing (Server: %s) :: Sending PING..." % self.server)
			self.pingCount += 1
			self.pingTime = time.time()
			self.sendMessage(["Action: PING"])
	
	def login(self):
		log.debug('AsteriskManagerProtocol.login (Server: %s) :: Logging in...' % (self.server))
		lines      = ['Action: login', 'Username: %s' % self.username, 'Secret: %s' % self.password, 'Events: on']
		linesDebug = ['Action: login', 'Username: %s' % self.username, 'Secret: ********', 'Events: on']
		log.debug('AsteriskManagerProtocol.login.login (Server: %s) :: Sending: %s' % (self.server, linesDebug))
		for line in lines:
			self.sendLine(line)
		self.sendLine('')
	
	def sendMessage(self, message):
		#log.debug("AsteriskManagerProtocol.sendMessage :: Sending: %s" % message)
		if type(message) == dict:
			message = ['%s: %s' % (k, v) for k, v in message.items()]
		for line in message:
			log.debug("AsteriskManagerProtocol.sendMessage (Server: %s) :: Sending: %s" % (self.server, line))
			self.sendLine(line.encode('UTF-8'))
		log.debug("AsteriskManagerProtocol.sendMessage (Server: %s) :: Sending: %s" % (self.server, ''))
		self.sendLine('')
		
	def lineReceived(self, line):
		log.debug("AsteriskManagerProtocol.lineReceived (Server: %s) :: Received: %s" % (self.server, line))
		self.messageBuffer[self.server].append(line)
		if not line.strip():
			self.processMessageBuffer()
		
	def processMessageBuffer(self):
		log.debug("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Running..." % self.server)
		message = {'Server': self.server}
		while self.messageBuffer[self.server]:
			line = self.messageBuffer[self.server].pop(0)
			line = line.strip()
			if line:
				if line.endswith('--END COMMAND--'):
					message.setdefault( ' ', []).extend([l for l in line.split('\n') if (l and l != '--END COMMAND--')])
				else:
					if line.startswith('Asterisk Call Manager'):
						self.amiVersion = line[len('Asterisk Call Manager')+1:].strip()
					else:
						try:
							key, value = line.split(':', 1)
						except:
							log.warning("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Improperly formatted line received and ignored: %r" % (self.server, line))
						else:
							message[key.strip()] = value.strip()
		
		Response = message.get('Response', None)
		Message  = message.get('Message', None)
		
		if Response == 'Pong' or (Response == 'Success' and message.get('Ping', None) == 'Pong'):
			log.debug("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Received PONG..." % self.server)
			self.pingCount -= 1
			PongHandler = self.factory.eventHandlers.get('onPong', None)
			if PongHandler:
				try:
					log.debug("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Executing onPong Handler" % self.server)
					message['Time'] = time.time() - self.pingTime
					PongHandler(message)
				except:
					log.exception("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Unhandled Exception in onPong Handler" % self.server)
			return
		
		if Response == 'Success' and Message == 'Authentication accepted':
			log.debug("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Authentication accepted..." % self.server)
			self.isAuthenticated = True
			self.pingCount = 0
			AuthHandler = self.factory.eventHandlers.get('onAuthenticationAccepted', None)
			if AuthHandler:
				try:
					log.debug("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Executing onAuthenticationAccepted Handler" % self.server)
					AuthHandler(message)
				except:
					log.exception("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Unhandled Exception in onAuthenticationAccepted Handler" % self.server)
			return
		
		if Response == 'Error' and Message == 'Authentication failed':
			log.error("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Authentication failed..." % self.server)
			self.isAuthenticated = False
			AuthHandler = self.factory.eventHandlers.get('onAuthenticationFailed', None)
			if AuthHandler:
				try:
					log.debug("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Executing onAutheticationFailed Handler" % self.server)
					AuthHandler(message)
				except:
					log.exception("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Unhandled Exception in onAutheticationFailed Handler" % self.server)
			return
		
		if Response == 'Error':
			log.error("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: AMI Error: %s" % (self.server, Message))
			return
		
		Event = message.get('Event', None)
		if Event:
			EventHandler        = self.factory.eventHandlers.get(Event, None)
			DefaultEventHandler = self.factory.eventHandlers.get('DefaultEventHandler', None)
			try:
				if EventHandler:
					log.debug("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Executing EventHandler for %s" % (self.server, Event))
					EventHandler(message)
				elif DefaultEventHandler:
					log.debug("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Executing DefaultEventHandler for %s" % (self.server, Event))
					DefaultEventHandler(message)
				else:
					log.debug("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Unhandled Event %s" % (self.server, Event))
			except:
				log.exception("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Unhandled Exception in EventHandler for %s" % (self.server, Event))
				print message
			return
				
		ActionID = message.get('ActionID', None)
		if ActionID:
			ActionHandler = self.factory.actionHandlers[self.server].get(ActionID, None)
			if ActionHandler:
				try:
					log.debug("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Executing ActionHandler for ActionID %s" % (self.server, ActionID))
					ActionHandler(message)
				except:
					log.exception("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Unhandled Exception in ActionHandler for ActionID %s" % (self.server, ActionID))
				log.debug("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Unregister ActionHandler for ActionID: %s" % (self.server, ActionID))
				del self.factory.actionHandlers[self.server][ActionID]
			else:
				log.debug("AsteriskManagerProtocol.processMessageBuffer (Server: %s) :: Unhandled response for ActionID %s" % (self.server, ActionID))
			return
		
##
## AsteriskManagerFactory
##
class AsteriskManagerFactory(protocol.ClientFactory):
	
	protocol       = AsteriskManagerProtocol
	closed         = False
	servers        = {} 
	amiVersion     = None
	eventHandlers  = {}
	actionHandlers = {}
	actionCount    = 0
	
	def __init__(self):
		pass
	
	def clientConnectionLost(self, connector, reason):
		if self.closed:
			log.debug("AsteriskManagerFactory.clientConnectionLost :: Connection Closed to %s at %s:%s" % (connector.servername, connector.hostname, connector.port))
		else:
			log.warning("AsteriskManagerFactory.clientConnectionLost :: Connection Lost to %s at %s:%s -- %s" % (connector.servername, connector.hostname, connector.port, reason.value))
			#log.debug("AsteriskManagerFactory.clientConnectionLost :: Reconnecting...")
			reactor.callLater(30, connector.connect)
	
	def clientConnectionFailed(self, connector, reason):
		log.error("AsteriskManagerFactory.clientConnectionFailed :: Connection Failed to %s at %s:%s -- %s" % (connector.servername, connector.hostname, connector.port, reason.value))
		reactor.callLater(30, connector.connect)
	
	def addServer(self, servername, hostname, port, username, password):
		self.servers[servername]        = {'hostname': hostname, 'port': port, 'username': username, 'password': password, 'protocol': None}
		self.actionHandlers[servername] = {}
	
	def connect(self):
		for server in self.servers:
			s = self.servers[server]
			log.debug("AsteriskManagerFactory.connect :: Trying to connect to %s at %s:%s" \
				% (server, s['hostname'], s['port']))
			p = reactor.connectTCP(s['hostname'], s['port'], self)
			p.servername = server
			p.hostname   = s['hostname']
			p.port       = s['port']
			p.username   = s['username']
			p.password   = s['password']
		
	def start(self):
		self.connect()
		
	def close(self):
		self.closed = True
		for server in self.servers:
			proc = self.servers[server]['protocol']
			try:
				proc.close()
			except:
				pass
		
	def disconnect(self):
		log.debug("AsteriskManagerFactory.disconnect :: Disconnecting from %s:%s" % (self.hostname, self.port))
		
	def registerEventHandler(self, event, handler):
		log.debug('AsteriskManagerFactory.registerEventHandler :: Register EnventHandler for %s' % event)
		self.eventHandlers[event] = handler
		
	def unregisterEventHandler(self, event):
		log.debug('AsteriskManagerFactory.unregisterEventHandler :: Unregister EnventHandler for %s' % event)
		try:
			del self.eventHandlers[event]
		except:
			log.error('AsteriskManagerFactory.unregisterEventHandler :: Event Handler not found: %s' % event)
	
	def generateActionId(self):
		self.actionCount += 1
		return 'ID.%06d' % self.actionCount
	
	def execute(self, **args):
		Server   = args.get('Server', None)
		Action   = args.get('Action', None)
		Handler  = args.get('Handler', None)

		for k in args:
			if k not in ('Server', 'Action', 'Handler'):
				log.warning("AsteriskManagerFactory.execute :: Invalid parameter: %s" % k)
		
		if not Action:
			log.error("AsteriskManagerFactory.execute :: No Action Defined...")
			return
		
		if not Server:
			for Server in self.servers:
				self.execute(Action = Action, Handler = Handler, Server = Server)
			return
		
		p = None
		try:
			p = self.servers[Server]['protocol']
			if not p:
				log.error("AsteriskManagerFactory.execute (Server: %s) :: Protocol not connected..." % Server)
				return
		except KeyError:
			log.error("AsteriskManagerFactory.execute :: Server not found: %s" % Server)
			return
		
		if Handler:
			ActionID = Action.get('ActionID', None)
			if not ActionID:
				ActionID = self.generateActionId()
			Action['ActionID'] = ActionID
			log.debug("AsteriskManagerFactory.execute (Server: %s) :: Registering ActionHandler for ActionID %s" % (Server, ActionID))
			self.actionHandlers[Server][ActionID] = Handler
		
		if p.isConnected:
			if p.isAuthenticated:
				p.sendMessage(Action)
			else:
				log.warning("AsteriskManagerFactory.execute (Server: %s) :: AMI Not Authenticated..." % p.server)
		else:
			log.warning("AsteriskManagerFactory.execute  (Server: %s) :: AMI Not Connected..." % p.server)
