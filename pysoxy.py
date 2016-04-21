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
VER = '\x05'
'''Method constants'''
#  '00' NO AUTHENTICATION REQUIRED
M_NOAUTH          = '\x00'
#  '02' USERNAME/PASSWORD
M_AUTH            = '\x02'
#  'FF' NO ACCEPTABLE METHODS
M_NOTAVAILABLE    = '\xff'
'''Command constants'''
#  CONNECT '01'
CMD_CONNECT         = '\x01'
#  BIND '02'
CMD_BIND            = '\x02'
#  UDP ASSOCIATE '03'
CMD_UDP_ASSOCIATIVE = '\x03'
'''Address type constants'''
#  IP V4 address '01'
ATYP_IPV4           = '\x01'
#  DOMAINNAME '03'
ATYP_DOMAINNAME     = '\x03'
#  IP V6 address '04'
ATYP_IPV6           = '\x04'
#
# Proxy Loop
#
def proxy_loop(socketSrc,socketDst):
   while(1):
      try:
         reader, _, _ = select.select([socketSrc, socketDst], [], [], 1)
      except select.error:
         return
      if not reader: return
      for socket in reader:
         data = socket.recv(BUFSIZE)
         if not data: return
         if socket is socketDst: socketSrc.send(data)
         else: socketDst.send(data)
#
# Make connection to the destination host
#
def connectToDst(DST_ADDR, DST_PORT):
   try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.settimeout(TIMEOUT_SOCKET)
      s.connect((DST_ADDR,DST_PORT))
      return s
   except socket.error, e:
      print 'Failed to create socket - Code: ' + str(e[0]) + ', Message: ' + e[1]
      return 0
#
# Request details
#
def request(socketSrc):
   try:
      REP = '\x07'
      #+----+-----+-------+------+----------+----------+
      #|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
      #+----+-----+-------+------+----------+----------+
      s5Request = socketSrc.recv(BUFSIZE)
      # check VER, CMD and RSV
      if (s5Request[0] != VER or s5Request[1] != CMD_CONNECT or s5Request[2] != '\x00'):
         return False
      # IPV4
      if s5Request[3] == ATYP_IPV4:
         DST_ADDR = '.'.join(str(ord(i)) for i in s5Request[4:-2])
         DST_PORT = unpack('>H', s5Request[8:])[0]
         print 'DST:', DST_ADDR, DST_PORT
         socketDst = connectToDst(DST_ADDR, DST_PORT)
         REP = '\x01' if socketDst == 0 else '\x00'
      # DOMAINNAME
      if s5Request[3] == ATYP_DOMAINNAME:
         SZ_DOMAINNAME = ord(s5Request[4])
         DOMAINNAME = s5Request[5:SZ_DOMAINNAME+5-len(s5Request)] if SZ_DOMAINNAME+5-len(s5Request) < 0 else s5Request[5:]
         print 'DOMAINNAME', repr(DOMAINNAME)
         return False
      # reply
      #+----+-----+-------+------+----------+----------+
      #|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
      #+----+-----+-------+------+----------+----------+
      reply = VER+REP+'\x00'+s5Request[3]+'\x00'+'\x00'+'\x00'+'\x00'+'\x00'+'\x00'
      socketSrc.sendall(reply)
      # start proxy
      proxy_loop(socketSrc,socketDst)
      socketSrc.close()
      socketDst.close()
   except Exception,e:
      print 'request:', str(e)
      return False
#
# Subnegotiation
#
def subnegotiation(wrapper):
   try:
      print 'SOCKS request'
      res = False
      # Version identifier/method selection message
      #+----+----------+----------+
      #|VER | NMETHODS | METHODS  |
      #+----+----------+----------+
      IdentificationPacket = wrapper.recv(BUFSIZE)
      # VER field
      if (VER != IdentificationPacket[0]):
         return res
      # METHODS fields
      NMETHODS = ord(IdentificationPacket[1])
      METHODS = IdentificationPacket[2:]
      if  (len(METHODS) != NMETHODS):
         return res 
      for METHOD in METHODS:
         if(METHOD == M_NOAUTH):
            break
      if(METHOD != M_NOAUTH and METHOD != M_AUTH): METHOD = M_NOTAVAILABLE
      else: res = True
      # METHOD selection message
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
def createSocket():
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
def exit_handler(signal, frame):
   exit(0)
#
# Main
#
newSocket = createSocket()
if not newSocket:
   print "Failed to create server"
   exit(0)
signal(SIGINT, exit_handler)
signal(SIGTERM, exit_handler)
while(1):
   if threading.activeCount() < MAX_THREADS:
      # accept
      try:
         wrapper, addr = newSocket.accept()
         wrapper.setblocking(1)
      except Exception,e:
         continue
      # thread incoming connection
      def connection(wrapper):
            if subnegotiation(wrapper):
               request(wrapper)
      recvThread = Thread(target=connection, args=(wrapper, ))
      recvThread.start()
   else:
      sleep(3)
   ## end while
wrapper.close()
newSocket.close()
