#!/usr/bin/python
# -*- coding: utf-8 -*-
#
#	tcprelay.py - TCP connection relay for usbmuxd
#
# Copyright (C) 2009	Hector Martin "marcan" <hector@marcansoft.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 or version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

import sys
import select
from optparse import OptionParser
from six import PY3
from six.moves import socketserver

from pymobiledevice.usbmux import usbmux


class SocketRelay(object):
	def __init__(self, a, b, maxbuf=65535):
		self.a = a
		self.b = b
		self.atob = ""
		self.btoa = ""
		if PY3:
			self.atob = b""
			self.btoa = b""
		self.maxbuf = maxbuf
	def handle(self):
		while True:
			rlist = []
			wlist = []
			xlist = [self.a, self.b]
			if self.atob:
				wlist.append(self.b)
			if self.btoa:
				wlist.append(self.a)
			if len(self.atob) < self.maxbuf:
				rlist.append(self.a)
			if len(self.btoa) < self.maxbuf:
				rlist.append(self.b)
			rlo, wlo, xlo = select.select(rlist, wlist, xlist)
			if xlo:
				return
			if self.a in wlo:
				n = self.a.send(self.btoa)
				self.btoa = self.btoa[n:]
			if self.b in wlo:
				n = self.b.send(self.atob)
				self.atob = self.atob[n:]
			if self.a in rlo:
				s = self.a.recv(self.maxbuf - len(self.atob))
				if not s:
					return
				self.atob += s
			if self.b in rlo:
				s = self.b.recv(self.maxbuf - len(self.btoa))
				if not s:
					return
				self.btoa += s
			#print("Relay iter: %8d atob, %8d btoa, lists: %r %r %r"%(len(self.atob), len(self.btoa), rlo, wlo, xlo))


class TCPRelay(socketserver.BaseRequestHandler):
	def handle(self):
		if 'options' in globals():
			sockpath = options.sockpath
		else:
			sockpath = None	
		mux = usbmux.USBMux(sockpath)
		print("Waiting for devices...")
		mux.process(1.0)
	
		dev = None
		if 'options' in globals():
			udid = options.udid
		else:
			udid = self.server.udid
		if udid:
			for device in mux.devices:
				if device.serial == udid:
					dev = device
					break
			if not dev:
				for _ in range(20):
					mux.process(0.5)
					for device in mux.devices:
						if device.serial == udid:
							dev = device
							break
					if dev :
						break	
		else:
			dev = mux.devices[0]
			
		if not mux.devices:
			print("No device found")
			self.request.close()
			return
		print("Connecting to device %s"%str(dev))
		dsock = mux.connect(dev, self.server.rport)
		lsock = self.request
		print("Connection established, relaying data")
		try:
			fwd = SocketRelay(dsock, lsock, self.server.bufsize * 1024)
			fwd.handle()
		finally:
			dsock.close()
			lsock.close()
			print("Connection closed")


class TCPServer(socketserver.TCPServer):
	allow_reuse_address = True


class ThreadedTCPServer(socketserver.ThreadingMixIn, TCPServer):
	pass


def forward_ports(pair_ports, udid=None, threaded=True, bufsize=128):
	'''iOS真机设备的端口转发
	
	:param pair_ports: 端口对的数组，每对端口中前一个代表远程端口，后一个代表本地端口，例如：["8100:8100", "8200:8200"]
	:type pair_ports: list
	'''
	servers=[]
	if threaded:
		serverclass = ThreadedTCPServer
	else:
		serverclass = TCPServer
		
	for pair_port in pair_ports:
		rport, lport = pair_port.split(":")
		rport = int(rport)
		lport = int(lport)
		print("Forwarding local port %d to remote port %d"%(lport, rport))
		server = serverclass(("localhost", lport), TCPRelay)
		server.rport = rport
		server.bufsize = bufsize
		server.udid = udid
		servers.append(server)

	alive = True
	while alive:
		try:
			rl, wl, xl = select.select(servers, [], []) 
			for server in rl:
				server.handle_request()
		except:
			alive = False
	

if __name__ == '__main__':
	parser = OptionParser(usage="usage: %prog [OPTIONS] RemotePort[:LocalPort] [RemotePort[:LocalPort]]...")
	parser.add_option("-t", "--threaded", dest='threaded', action='store_true', default=False, help="use threading to handle multiple connections at once")
	parser.add_option("-b", "--bufsize", dest='bufsize', action='store', metavar='KILOBYTES', type='int', default=128, help="specify buffer size for socket forwarding")
	parser.add_option("-s", "--socket", dest='sockpath', action='store', metavar='PATH', type='str', default=None, help="specify the path of the usbmuxd socket")
	parser.add_option("-u", "--udid", dest='udid', action='store', metavar='UDID', type='str', default=None, help="specify the udid of iOS device")
	
	options, args = parser.parse_args()

	serverclass = TCPServer
	if options.threaded:
		serverclass = ThreadedTCPServer

	if len(args) == 0:
		parser.print_help()
		sys.exit(1)

	ports = []

	for arg in args:
		try:
			if ':' in arg:
				rport, lport = arg.split(":")
				rport = int(rport)
				lport = int(lport)
				ports.append((rport, lport))
			else:
				ports.append((int(arg), int(arg)))
		except:
			parser.print_help()
			sys.exit(1)

	servers=[]
	HOST = "localhost"
	
	for rport, lport in ports:
		print("Forwarding local port %d to remote port %d"%(lport, rport))
		server = serverclass((HOST, lport), TCPRelay)
		server.rport = rport
		server.bufsize = options.bufsize
		servers.append(server)

	alive = True
	
	while alive:
		try:
			rl, wl, xl = select.select(servers, [], [])
			for server in rl:
				server.handle_request()
		except:
			alive = False
