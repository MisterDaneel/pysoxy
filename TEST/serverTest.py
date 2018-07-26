# -*- coding: utf-8 -*-
import socket
from signal import signal, SIGINT, SIGTERM
from time import sleep
from sys import exit, platform
BUFSIZE    = 2048
LOCAL_ADDR = '0.0.0.0'
LOCAL_PORT = 5556
#
# Create Socket
#
def createSocket():
      try:
         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
         self.socket.close()
         return 0
      return s
#
# Main
#
socket = createSocket()
if socket == 0:
   print "Failed to create server"
   exit(0)
# accept
wrapper, addr = socket.accept()
while(1):
   data = wrapper.recv(BUFSIZE)
   if data:
      print data
      wrapper.sendall(data)
   else:
      wrapper.close()
      wrapper, addr = socket.accept()
wrapper.close()
socket.close()
