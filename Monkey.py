#!/usr/bin/python
# coding: latin-1


#
##
###
### Roaming Monkey: an Asterisk(tm) add-on to roam calls from (W)LAN to PSTN
###
### Copyright (c) 2011, Matí­as Javier Rossi - DokkoGroup
### All rights reserved.
###
##
#



import os
import re
import sys
from logging import FileHandler, StreamHandler
import time
import traceback
import socket
import signal
import random
import Queue
import logging
import optparse

from AsteriskManager import AsteriskManagerFactory
from ConfigParser import SafeConfigParser, NoOptionError

#from twisted.protocols import basic
from twisted.internet import reactor, task
#protocol, 

import distutils.sysconfig


##
##  Globals
##
##
## Global constants
SIP_CONF_FILENAME='sip.conf'
ONCALL_QUALIFY=1000
ONCALL_QUALIFYFREQ=1

SERVER_OPTIONAL_PARAMETERS=['sip_conf_filename', 'oncall_qualify', 'oncall_qualifyfreq']
CLIENT_OPTIONAL_PARAMETERS=['oncall_qualify', 'oncall_qualifyfreq']

DEFAULT_LOGFILE='/var/log/monkey.log'
DEFAULT_CONFIGFILE='/etc/monkey.conf'
DEFAULT_PIDFILE='/var/run/monkey.pid'

## Global Logger
log = logging.getLogger('Monkey')

## deamonize
def createDaemon():
	if os.fork() == 0:
		os.setsid()
		if os.fork() == 0:
			os.chdir('/')
			os.umask(0)
		else:
			os._exit(0)
	else:
		os._exit(0)
	
	pid = os.getpid()
	print '\nRoaming Monkey daemonized with pid %s' % pid
	f = open(DEFAULT_PIDFILE, 'w')
	f.write('%s' % pid)
	f.close()


def configureLogger(logfile):
	
	rootLogger = logging.getLogger()
	
	fmt = logging.Formatter(
	"[%(asctime)s] %(levelname)-8s :: %(message)s",
	'%a %b %d %H:%M:%S %Y'
	)

	try:
		rootLogger.addHandler(FileHandler(logfile))
	except IOError as (errno, strerror):
		print 'Cannot open log file %s. (%s: %s)' % (options.logFile, errno, strerror)
		sys.exit(errno)
	
	if options.daemon:
		createDaemon()
	else:
		rootLogger.addHandler(StreamHandler(sys.stdout))
	
	
	for handler in rootLogger.handlers:
		handler.setFormatter(fmt)
		
	rootLogger.setLevel(logging.WARNING)


def chan2user(channel):
	return channel.replace('SIP/','').split('-')[0]


##
## Configuration file parser
##
##


class MonkeyConfigParser(SafeConfigParser):
	def optionxform(self, optionstr):
		return optionstr


##
## Main application class
##
##


class Monkey:
	
	##
	## Internal Params
	##
	
	running         = True
	reloading       = False
	
	configFile      = None
	
	AMI             = None
	amiAuthCheck	= {}
	
	servers			= {}
	
	##
	## Class Initialization
	##
	def __init__(self, configFile):
		
		log.debug('Monkey :: Initializing...')
		
		self.configFile = configFile

		self.AMI = AsteriskManagerFactory()

		self.AMI.registerEventHandler('onAuthenticationAccepted', self.onAuthenticationAccepted)
		
		self.AMI.registerEventHandler('Status',		self.handlerStatus)
		self.AMI.registerEventHandler('PeerStatus',	self.handlerPeerStatus)
		self.AMI.registerEventHandler('Bridge',		self.handlerBridge)
		self.AMI.registerEventHandler('Hangup',		self.handlerHangup)
		
		self.initialize()
		

		
	def clearStatus(self):
		
		log.debug('Monkey.clearStatus :: Cleaning status')
		
		servers = None


		
	def initialize(self):
		
		log.debug('Monkey.initialize :: Running... ')
		
		self.parseConfig()

		for server in self.servers:
			s = self.servers[server]
			self.AMI.addServer(server, s['hostname'], s['hostport'], s['username'], s['password'])


	
	def parseConfig(self):
		
		## FIXME
		#root@pbx:~# service avarahamela start
		#Starting Avarahamela Asterisk add-on: avarahamela
		#Avarahamela daemonized with pid 12637
		#Traceback (most recent call last):
		#  File "/opt/avarahamela/avarahamela", line 549, in <module>
		#    app = Avarahamela(options.configFile)
		#  File "/opt/avarahamela/avarahamela", line 154, in __init__
		#    self.initialize()
		#  File "/opt/avarahamela/avarahamela", line 170, in initialize
		#    self.parseConfig()
		#  File "/opt/avarahamela/avarahamela", line 183, in parseConfig
		#    filesRead = cp.read(self.configFile)
		#  File "/usr/lib/python2.6/ConfigParser.py", line 286, in read
		#.
		#root@pbx:~#     self._read(fp, filename)
		#  File "/usr/lib/python2.6/ConfigParser.py", line 510, in _read
		#    raise e
		#ConfigParser.ParsingError: File contains parsing errors: /etc/avarahamela.conf
		#	[line 52]: 'Every monitored client has its own settings in a section delimited with square bracketsAs you can monitor many servers, you must map every client to the server it\n'
		#	[line 53]: 'belongs.\n'
		log.debug('Monkey.parseConfig :: Parsing config')
		
		cp = MonkeyConfigParser()
		filesRead = cp.read(self.configFile)
		if not self.configFile in filesRead:
			raise IOError(-1, 'Couldn\'t open config file %s' % self.configFile)
		
		
		servers = [s for s in cp.sections() if s.startswith('server:')]
		for server in servers:
			name = server.replace('server:', '').strip()

			# Try to read the mandatory parameters
			try:
				self.servers[name] = {
					'hostname'				: cp.get(server, 'hostname'),
					'hostport'				: int(cp.get(server, 'hostport')),
					'username'				: cp.get(server, 'username'),
					'password'				: cp.get(server, 'password'),
					'redirect_context'		: cp.get(server, 'redirect_context')
				}
			except NoOptionError as error:
				log.debug('Monkey.parseConfig :: NoOptionError exception in mandatory parameter for server definition')
				log.warning('The definition for server %s doesn\'t contain %s. Skipping the whole section...' % (name, error.option))
				continue
			
			# Try to read the optional parameters, defaulting to None
			for parameter in SERVER_OPTIONAL_PARAMETERS:
				try:
					self.servers[name][parameter] = cp.get(server, parameter)
				except NoOptionError:
					self.servers[name][parameter] = None

			# Initialize clients
			self.servers[name]['clients'] = {}
			

		
		
		clients = [s for s in cp.sections() if s.startswith('client:')]
		for client in clients:
			id		= client.replace('client:', '').strip().split()
			server	= id[0]
			user	= id[1]
			
			if not server in self.servers.keys():
				log.warning('Undefined server \'%s\' in client definition \'%s\'. Ignoring section...' % (server, client))
				continue
			
			try:
				self.servers[server]['clients'][user] = {
					'redirect_extension'	: cp.get(client, 'redirect_extension'),
				}
			except NoOptionError as error:
				log.debug('Monkey.parseConfig :: NoOptionError exception in mandatory parameter for client definition')
				log.warning('The definition for client %s in server %s doesn\'t contain %s. Skipping the whole section...' % (user, server, error.option))
				continue
			
			# Try to read the optional parameters, defaulting to None
			for parameter in CLIENT_OPTIONAL_PARAMETERS:
				try:
					self.servers[server]['clients'][user][parameter] = cp.get(client, parameter)
				except NoOptionError:
					self.servers[server]['clients'][user][parameter] = None

			# Initialize status
			self.servers[server]['clients'][user]['talking_with'] = None
			
			# Set default qualify and qualifyfreq values in 'None'. After successful
			# authentication with the server, we will get those values from sip.conf..
			self.servers[server]['clients'][user]['def_qualify'] = None
			self.servers[server]['clients'][user]['def_qualifyfreq'] = None
				
			# Mark the user as 'not ready'.
			# Will be available after we are done with server authentication and configuration fetching.
			self.servers[server]['clients'][user]['ready'] = False;

	##
	## AMI Handlers for Events
	##
	
	def handlerPeerStatus(self, event):
		
		log.debug('Monkey.handlerPeerStatus :: Running...')
		
		# *******************************************
		# Server: <server name>
		# PeerStatus: {Registered, Reachable, Unreachable, Unregistered}
		# Peer: (Example: SIP/207)
		# Address: <ip address>
		# Privilege: 
		# ChannelType: {SIP et al}
		# Port: 
		# Event: PeerStatus
		#  *******************************************

		server	= event['Server']
		user	= event['Peer'].replace('SIP/','')
		status	= event['PeerStatus']
		
		if status in ['Unreachable', 'Unregistered'] and user in self.servers[server]['clients'].keys():
			log.debug('Monkey.handlerPeerStatus :: User %s disconnected from server %s. Verifying status...' % (user, server))
			channel = self.servers[server]['clients'][user]['talking_with']
			if channel != None:
				log.debug('Monkey.handlerPeerStatus :: Trying to redirect...')
				self.redirect(server, user, channel)
			else:
				log.debug('Monkey.handlerPeerStatus :: User %s is not in a conversation (talking_with = None).' % user)

	
	def handlerStatus(self, event):
		
		log.debug('Monkey.handlerStatus :: Running...')
		log.debug(repr(event))
		# *******************************************
		# BridgedChannel: (Example: SIP/227-0000024d)
		# Accountcode: 
		# BridgedUniqueid: (Example: 1295469604.599)
		# Uniqueid: (Example: 1295469569.594)
		# Extension: (Example: 1234)
		# ChannelState: 6
		# CallerIDNum: 424761
		# Server: <server name>
		# Priority: 2
		# Seconds: 41
		# Context: greeting
		# CallerIDName: <caller id display name>
		# Privilege: {Call, ?}
		# Event: Status
		# Channel: (ExampÄºe: SIP/995-00000248}
		# ChannelStateDesc: Up
		# *******************************************
		
		server	= event['Server']
		user	= chan2user(event['Channel'])
		
		if user in self.servers[server]['clients'].keys():
			log.debug('Monkey.handlerStatus :: User %s is being monitored in server %s.' % (user, server))
			log.debug('Monkey.handlerStatus :: Starting qualification...')
			self.qualify(server, user)
			log.debug('Monkey.handlerStatus :: Storing channels...')
			counterpart	= event['BridgedChannel']
			self.servers[server]['clients'][user]['talking_with'] = counterpart
		 
		
	
	def handlerBridge(self, event):
		
		log.debug('Monkey.handlerBridge :: Running...')
		
		# *******************************************
		# Uniqueid2: (Example: 1295379611.340)
		# Uniqueid1: (Example: 1295379611.339)
		# CallerID2: <caller id name>
		# Bridgestate: {Link, ?}
		# CallerID1: <caller id name>
		# Server: <server name>
		# Channel2: (Example: SIP/250-0000014e)
		# Channel1: (Example: SIP/207-0000014d)
		# Bridgetype: {core, ?}
		# Privilege: {call, all, ?}
		# Event: Bridge
		# *******************************************
		
		for channel in [event['Channel1'], event['Channel2']]:
			self._askStatus(event['Server'], channel)
		
	def handlerHangup(self, event):
		
		log.debug('Monkey.handlerHangup :: Running...')

		# *******************************************
		# Event: Hangup
		# Privilege: call,all
		# SequenceNumber: 255587
		# File: channel.c
		# Line: 1841
		# Func: ast_hangup
		# Channel: SIP/207-00000ca7
		# Uniqueid: 1307456910.3248
		# CallerIDNum: 207
		# CallerIDName: Juan de los Palotes
		# Cause: 16
		# Cause-txt: Normal Clearing
		# *******************************************
		
		user = chan2user(event['Channel'])
		server = event['Server']
		if user in self.servers[server]['clients'].keys():
			log.debug('Monkey.handlerHangup :: User %s is being monitored in server %s.' % (user, server))
			log.debug('Monkey.handlerHangup :: Stopping qualification...')
			self.unqualify(server, user)
			log.debug('Monkey.handlerHangup :: Clearing channels...')
			self.servers[server]['clients'][user]['talking_with'] = None

	
	def getConfigHandler(self, event):

		log.debug('Monkey.getConfigHandler :: Running...')
		
		server	= event['Server']
		user	= event['Category-000000']
		
		eventKeys = event.keys()
		eventKeys.sort()
		
		for key in eventKeys:
			if key.startswith('Line-'):
				log.warning('LINE: %s' % event[key])
		
#		log.debug(repr(event))
	
	
	def onAuthenticationAccepted(self, event):
		
		server = event['Server']
		
		log.debug('Monkey.onAuthenticationAccepted :: Running for Server %s' % server)
		
		
		# Read 'qualify' and 'qualifyfreq' values from sip.conf.
		for user in self.servers[server]['clients'].keys():
			action = {
					'Action'	: 'GetConfig',
					'Filename'	: self.sipConfFilename(server),
					'Category'	: user
					}

			self.AMI.execute(Server = server, Action = action, Handler = self.getConfigHandler)
		
		self._askStatus(server)

	
	##
	## Auxiliar methods
	##
	def sipConfFilename(self, server):
		
		log.debug('Monkey.sipConfFilename :: Running...')
		
		answer = SIP_CONF_FILENAME;
		if self.servers[server]['sip_conf_filename'] != None:
			answer = self.servers[server]['sip_conf_filename']
		return answer
			
	def _askStatus(self, server, channel = None):
		
		log.debug('Monkey._askStatus :: Running...')
		
		action = {'Action'	: 'Status'}
		if channel != None:
			action['Channel'] = channel
		
		self.AMI.execute(Server = server, Action = action)
	
	def setQualification(self, server, user, qualify, qualifyfreq):
		log.debug('Monkey.setQualify :: Running...')
		
		if not self.servers[server]['clients'][user]['ready']:
			log.warning('Monkey.setQualify :: NO! I will not qualify user %s until it is ready!' % user)
			return
		
		log.debug('Monkey.setQualify :: Going to qualify %s with q=%s qf=%s' % (user, qualify, qualifyfreq))
		
		filename = self.sipConfFilename(server) 
		
		# Remove qualify setting for the user
		action = {
				'Action'		: 'UpdateConfig',
				'Reload'		: 'no',		# Don't reload. Will refresh settings in the following acrion.
				'SrcFilename'	: filename,
				'DstFilename'	: filename,
				'Action-000000'	: 'Delete',
				'Cat-000000'	: user,
				'Var-000000'	: 'qualify'
				}
		
		self.AMI.execute(Server = server, Action = action)
		
		# Remove qualifyfreq setting for the same user
		action = {
				'Action'		: 'UpdateConfig',
				'Reload'		: 'yes',	# Reload to make the change effective
				'SrcFilename'	: filename,
				'DstFilename'	: filename,
				'Action-000000'	: 'Delete',
				'Cat-000000'	: user,
				'Var-000000'	: 'qualifyfreq'
				}
		
		self.AMI.execute(Server = server, Action = action)
		
		if qualify != None:
			# Add qualify setting for the user
			action = {
					'Action'		: 'UpdateConfig',
					'Reload'		: 'no',		# Same as before. No need to reload until both changes were commited
					'SrcFilename'	: filename,
					'DstFilename'	: filename,
					'Action-000000'	: 'Append',
					'Cat-000000'	: user,
					'Var-000000'	: 'qualify',
					'Value-000000'	: qualify
					}
			
			self.AMI.execute(Server = server, Action = action)
		
		if qualifyfreq != None:
			# Append qualifyfreq setting for the same user
			action = {
					'Action'		: 'UpdateConfig',
					'Reload'		: 'yes',	# Reload to make the changes effective
					'SrcFilename'	: filename,
					'DstFilename'	: filename,
					'Action-000000'	: 'Append',
					'Cat-000000'	: user,
					'Var-000000'	: 'qualifyfreq',
					'Value-000000'	: qualifyfreq
					}
			
			self.AMI.execute(Server = server, Action = action)
		


	def qualify(self, server, user):
		log.debug('Monkey.qualify :: Running...')
		
		qualify = ONCALL_QUALIFY
		if self.servers[server]['clients'][user]['oncall_qualify'] != None:
			qualify = self.servers[server]['clients'][user]['oncall_qualify']
		elif self.servers[server]['oncall_qualify'] != None:
			qualify = self.servers[server]['oncall_qualify']

		qualifyfreq = ONCALL_QUALIFYFREQ
		if self.servers[server]['clients'][user]['oncall_qualifyfreq'] != None:
			qualifyfreq = self.servers[server]['clients'][user]['oncall_qualifyfreq']
		elif self.servers[server]['oncall_qualifyfreq'] != None:
			qualifyfreq = self.servers[server]['oncall_qualifyfreq']
				
		self.setQualification(server, user, qualify, qualifyfreq)


		
		
	def unqualify(self, server, user):
		log.debug('Monkey.unqualify :: Running...')
		
		self.setQualification(server, user, None, None)
		
		
	def redirect(self, server, user, channel):
		
		# user: user who got disconnected. The channel to redirect is stored in the user entry.
		log.debug('Monkey.redirect :: Running...')
		
		context		= self.servers[server]['redirect_context']
		extension	= self.servers[server]['clients'][user]['redirect_extension']
		priority	= 1

		log.debug('Monkey.redirect :: Executing "Redirect %s to (%s : %s : %s)...' % (channel, context, extension, priority))
		self.AMI.execute(
						Server = server,
						Action = {
								'Action'	: 'Redirect',
								'Channel'	: channel,
								'Context'	: context,
								'Exten'		: extension,
								'Priority'	: priority
						}
		)


	
	def start(self):
		
		log.debug('Monkey.start :: Starting Roaming Monkey...')
		signal.signal(signal.SIGUSR1, self._sigUSR1)
		signal.signal(signal.SIGTERM, self._sigTERM)
		signal.signal(signal.SIGINT, self._sigTERM)
		
		self.AMI.start()
		reactor.run()
		self.running = False
		self.AMI.close()
		
		log.debug('Monkey :: Finished...')

	
	
	def _sigUSR1(self, *args):
		
		log.debug('Monkey :: Received SIGUSR1 -- Dumping Vars...')

		log.debug('self.servers = %s' % repr(self.servers))

		
		
	def _sigTERM(self, *args):
		
		log.debug('Monkey :: Received SIGTERM -- Shutting Down...')
		self.AMI.close()
		reactor.stop()

		
		
if __name__ == '__main__':
	
## Options
	opt = optparse.OptionParser()

	opt.add_option('-c', '--config',
		dest    = "configFile",
		default = DEFAULT_CONFIGFILE,
		help    = "use this config file instead of %s" % DEFAULT_CONFIGFILE
	)
	
	opt.add_option('-d', '--daemon',
		dest   = "daemon",
		action = "store_true",
		help   = "deamonize (fork in background)"
	)

	opt.add_option('-l', '--logfile',
		dest    = "logFile",
		default = DEFAULT_LOGFILE,
		help    = "use this log file instead of %s" % DEFAULT_LOGFILE
	)
	
	opt.add_option('--version',
				dest 	= 'version',
				action 	= 'store_true',
				default	= False,
				help	= 'show version')
	
	opt.add_option('-q', '--quiet',
				dest	= 'quiet',
				action	= 'store_true',
				help	= 'hides output messages')
	
	(options, args) = opt.parse_args()
	

## Actions

	configureLogger(options.logFile)

	if options.version:
		print 'Roaming Monkey (tm). Development release.'
		sys.exit()
	
	# Show everything by default
	log.setLevel(logging.DEBUG)
	# If the option quiet is enabled, then show only fatal events 
	if options.quiet:
		log.setLevel(logging.FATAL)
	
	log.info("Starting...")
	try:
		app = Monkey(options.configFile)
	except IOError as (errno, strerror):
		log.fatal("%s" % strerror)
		sys.exit(errno)
		
	app.start()
	
