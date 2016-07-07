# -*- coding: utf-8 -*-
#
# Small Socks5 Proxy Server in Python (2.7)
# from https://github.com/MisterDaneel/
#

# Network
import ssl
import socket
import select
from struct import pack, unpack
# System
from signal import signal, SIGINT, SIGTERM
import threading
from threading import Thread
from time import sleep
from sys import exit

#
# Configuration
#
TUNNEL          = False
SSL_SERVER_ADDR = ''
SSL_SERVER_PORT = 0
MAX_THREADS     = 50
BUFSIZE         = 2048
TIMEOUT_SOCKET  = 5
LOCAL_ADDR      = '0.0.0.0'
LOCAL_PORT      = 5555

#
# Constants
#
'''Version of the protocol'''
# PROTOCOL VERSION 5
VER             = '\x05'
'''Method constants'''
# '00' NO AUTHENTICATION REQUIRED
M_NOAUTH        = '\x00'
# 'FF' NO ACCEPTABLE METHODS
M_NOTAVAILABLE  = '\xff'
'''Command constants'''
# CONNECT '01'
CMD_CONNECT     = '\x01'
'''Address type constants'''
# IP V4 address '01'
ATYP_IPV4       = '\x01'
# DOMAINNAME '03'
ATYP_DOMAINNAME = '\x03'

#
# Error
#
def Error():
   import sys
   exc_type, _, exc_tb = sys.exc_info()
   print exc_type, exc_tb.tb_lineno

#
# Proxy Loop
#
def Proxy_Loop(socket_src, socket_dst):
   while(1):
      try:
         reader, _, _ = select.select([socket_src, socket_dst], [], [], 1)
      except select.error:
         return
      if not reader:
         return
      try:
         for sock in reader:
            data = sock.recv(BUFSIZE)
            if not data:
               continue
            if sock is socket_dst:
               socket_src.send(data)
            else:
               socket_dst.send(data)
      except socket.error, e:
         print 'Loop failed - Code: ' + str(e[0]) + ', Message: ' + e[1]
         return 0
   # end while

#
# Tunnel Loop
#
def Tunnel_Loop(socket_src, socket_ssl, ):
   while(1):
      try:
         reader, _, _ = select.select([socket_src, socket_dst], [], [], 1)
      except select.error:
         return
      if not reader:
         return
      for sock in reader:
         data = sock.recv(BUFSIZE)
         if not data:
            return
         if sock is socket_dst:
            socket_src.send(data)
         else:
            socket_dst.send(data)
   # end while
  
#
# Make connection to the destination host
#
def Connect_To_Dst(dst_addr, dst_port):
   try:
      s = Create_Socket()
      s.connect((dst_addr,dst_port))
      return s
   except socket.error, e:
      print 'Failed to connect to DST - Code: ' + str(e[0]) + ', Message: ' + e[1]
      return 0
   except:
      Error()
      return 0

#
# Make connection to the SSL Server
#
def Connect_To_SSL_Server(s):
   try:
      ssl_socket = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
      ssl_socket.connect((SSL_SERVER_ADDR, SSL_SERVER_PORT))
      return ssl_socket
   except socket.error, e:
      print 'Failed to connect to SSL server - Code: ' + str(e[0]) + ', Message: ' + e[1]
      return 0

#
# Request details
#
def Request(socket_src):
   try:
      # Client Request
      #+----+-----+-------+------+----------+----------+
      #|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
      #+----+-----+-------+------+----------+----------+
      s5_request = socket_src.recv(BUFSIZE)
      # Check VER, CMD and RSV
      if (s5_request[0] != VER or s5_request[1] != CMD_CONNECT or s5_request[2] != '\x00'):
         return False
      # IPV4
      if s5_request[3] == ATYP_IPV4:
         dst_addr = socket.inet_ntoa(s5_request[4:-2])#'.'.join(str(ord(i)) for i in s5_request[4:-2])
         dst_port = unpack('>H', s5_request[8:len(s5_request)])[0]
      # DOMAIN NAME
      if s5_request[3] == ATYP_DOMAINNAME:
         sz_domain_name = ord(s5_request[4])
         dst_addr = s5_request[5: 5 + sz_domain_name - len(s5_request)]
         dst_port = unpack('>H', s5_request[5 + sz_domain_name:len(s5_request)])[0]
      print 'DST:', dst_addr, dst_port
   except:
      if socket_src != 0:
         socket_src.close()
      Error()
      return False
   try:
      # Server Reply
      #+----+-----+-------+------+----------+----------+
      #|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
      #+----+-----+-------+------+----------+----------+
      REP = '\x07'
      BND = '\x00' + '\x00' + '\x00' + '\x00' + '\x00' + '\x00'
      # SSL TUNNEL
      if TUNNEL:
         remote_server = Create_Socket()
         ssl_socket = Connect_To_Ssl_Server(remote_server)
         if ssl_socket == 0:
            REP = '\x01'
         else:
            REP = '\x00'
            BND = socket.inet_aton(remote_server.getsockname()[0])
            BND += pack(">H", remote_server.getsockname()[1])
      # SOCKS PROXY
      else:
         socket_dst = Connect_To_Dst(dst_addr, dst_port)
         if socket_dst == 0:
            REP = '\x01'
         else:
            REP = '\x00'
            BND = socket.inet_aton(socket_dst.getsockname()[0])
            BND += pack(">H", socket_dst.getsockname()[1])
      reply = VER + REP + '\x00' + ATYP_IPV4
      reply += BND
      socket_src.sendall(reply)
      # start tunnel
      if TUNNEL and REP == '\x00':
         Tunnel_Loop(socket_src, ssl_socket, addr, port[0])
      # start proxy
      elif REP == '\x00':
         Proxy_Loop(socket_src, socket_dst)
      if socket_src != 0:
         socket_src.close()
      if socket_dst != 0:
         socket_dst.close()
   except:
      if socket_src != 0:
         socket_src.close()
      Error()
      return False

#
# Subnegotiation
#
def Subnegotiation(wrapper):
   try:
      res = False
      # Client Version identifier/method selection message
      #+----+----------+----------+
      #|VER | NMETHODS | METHODS  |
      #+----+----------+----------+
      identification_packet = wrapper.recv(BUFSIZE)
      # VER field
      if (VER != identification_packet[0]):
         return res
      # METHODS fields
      NMETHODS = ord(identification_packet[1])
      METHODS = identification_packet[2: ]
      if (len(METHODS) != NMETHODS):
         return res 
      for METHOD in METHODS:
         if(METHOD == M_NOAUTH):
            break
      if (METHOD != M_NOAUTH and METHOD != M_AUTH):
	     METHOD = M_NOTAVAILABLE
      else:
	     res = True
      # Server Method selection message
      #+----+--------+
      #|VER | METHOD |
      #+----+--------+
      reply = VER + METHOD
      wrapper.sendall(reply)
      return res
   except:
      Error()
      return False

#
# Create socket
#
def Create_Socket():
      try:
         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         s.settimeout(TIMEOUT_SOCKET)
      except socket.error, e:
         print 'Failed to create socket - Code: ' + str(e[0]) + ', Message: ' + e[1]
         return 0
      return s

#
# Bind_Port
#
def Bind_Port(s):
      # Bind
      try:
         print 'Bind', str(LOCAL_PORT)
         s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
         s.bind((LOCAL_ADDR,LOCAL_PORT))
      except socket.error , e:
         print 'Bind failed in server - Code: ' + str(e[0]) + ', Message: ' + e[1]
         s.close()
         return 0
      # Listen
      try:
         print "Listen"
         s.listen(10)
      except socket.error, e:
         print "Listen failed - Code: " + str(e[0]) + ", Message: " + e[1]
         s.close()
         return 0
      return s

#
# Exit
#
def Exit_Handler(signal, frame):
   exit(0)

#
# Main
#
if __name__ == '__main__':
	new_socket = Create_Socket()
	Bind_Port(new_socket)
	if not new_socket:
	   print "Failed to create server"
	   exit(0)
	signal(SIGINT, Exit_Handler)
	signal(SIGTERM, Exit_Handler)
	while(1):
	   if threading.activeCount() < MAX_THREADS:
		  # Accept
		  try:
			 wrapper, addr = new_socket.accept()
			 wrapper.setblocking(1)
		  except:
			 continue
		  # Thread incoming connection
		  def Connection(wrapper):
				if Subnegotiation(wrapper):
				   Request(wrapper)
		  recv_thread = Thread(target=Connection, args=(wrapper, ))
		  recv_thread.start()
	   else:
		  sleep(3)
	   # end while
	wrapper.close()
	new_socket.close()
