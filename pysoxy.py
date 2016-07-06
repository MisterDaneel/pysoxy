# -*- coding: utf-8 -*-
#
# Small Socks5 Proxy Server in Python (2.7)
# from https://github.com/MisterDaneel/
#

# Network
import socket
import select
from struct import unpack
# System
from signal import signal, SIGINT, SIGTERM
import threading
from threading import Thread
from time import sleep
from sys import exit

#
# Configuration
#
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
# Proxy Loop
#
def ProxyLoop(socket_src, socket_dst):
   while(1):
      try:
         reader, _, _ = select.select([socket_src, socket_dst], [], [], 1)
      except select.error:
         return
      if not reader:
         return
      for socket in reader:
         data = socket.recv(BUFSIZE)
         if not data:
            return
         if socket is socket_dst:
            socket_src.send(data)
         else:
            socket_dst.send(data)
   # end while

#
# Make connection to the destination host
#
def ConnectToDst(dst_addr, dst_port):
   try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.settimeout(TIMEOUT_SOCKET)
      s.connect((dst_addr,dst_port))
      return s
   except socket.error, e:
      print 'Failed to create socket - Code: ' + str(e[0]) + ', Message: ' + e[1]
      return 0

#
# Request details
#
def Request(socket_src):
   try:
      REP = '\x07'
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
         dst_addr = '.'.join(str(ord(i)) for i in s5_request[4:-2])
         dst_port = unpack('>H', s5_request[8:])[0]
         print 'DST:', dst_addr, dst_port
         socket_dst = ConnectToDst(dst_addr, dst_port)
         REP = '\x01' if socket_dst == 0 else '\x00'
      # DOMAINNAME
      if s5_request[3] == ATYP_DOMAINNAME:
         SZ_DOMAINNAME = ord(s5_request[4])
         DOMAINNAME = s5_request[5:SZ_DOMAINNAME+5-len(s5_request)] if SZ_DOMAINNAME+5-len(s5_request) < 0 else s5_request[5:]
         print 'DOMAINNAME', repr(DOMAINNAME)
         return False
      # Server Reply
      #+----+-----+-------+------+----------+----------+
      #|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
      #+----+-----+-------+------+----------+----------+
      reply = VER+REP+'\x00'+s5_request[3]+'\x00'+'\x00'+'\x00'+'\x00'+'\x00'+'\x00'
      socket_src.sendall(reply)
      # start proxy
      ProxyLoop(socket_src,socket_dst)
      socket_src.close()
      socket_dst.close()
   except Exception,e:
      print 'request:', str(e)
      return False

#
# Subnegotiation
#
def Subnegotiation(wrapper):
   try:
      print 'SOCKS request'
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
      METHODS = identification_packet[2:]
      if (len(METHODS) != NMETHODS):
         return res 
      for METHOD in METHODS:
         if(METHOD == M_NOAUTH):
            break
      if(METHOD != M_NOAUTH and METHOD != M_AUTH): METHOD = M_NOTAVAILABLE
      else: res = True
      # Server Method selection message
      #+----+--------+
      #|VER | METHOD |
      #+----+--------+
      reply = VER+METHOD
      wrapper.sendall(reply)
      return res
   except Exception,e:
      print 'handshake:', str(e)
      return False

#
# Create socket
#
def CreateSocket():
      try:
         print 'Create Socket'
         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
         s.settimeout(TIMEOUT_SOCKET)
      except socket.error, e:
         print 'Failed to create socket - Code: ' + str(e[0]) + ', Message: ' + e[1]
         return 0
      # bind
      try:
         print 'Bind', str(LOCAL_PORT)
         s.bind((LOCAL_ADDR,LOCAL_PORT))
      except socket.error , e:
         print 'Bind failed in server - Code: ' + str(e[0]) + ', Message: ' + e[1]
         s.close()
         return 0
      # listen
      try:
         print "Listen"
         s.listen(10)
      except socket.error, e:
         print "Listen failed - Code: "  + str(e[0]) + ", Message: " + e[1]
         s.close()
         return 0
      return s

#
# Exit
#
def ExitHandler(signal, frame):
   exit(0)

#
# Main
#
new_socket = CreateSocket()
if not new_socket:
   print "Failed to create server"
   exit(0)
signal(SIGINT, ExitHandler)
signal(SIGTERM, ExitHandler)
while(1):
   if threading.activeCount() < MAX_THREADS:
      # accept
      try:
         wrapper, addr = new_socket.accept()
         wrapper.setblocking(1)
      except Exception,e:
         continue
      # thread incoming connection
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
