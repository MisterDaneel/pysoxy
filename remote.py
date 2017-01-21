# Network
import socket
import select
import ssl
#from struct import pack, unpack
# System
from signal import signal, SIGINT, SIGTERM
from threading import Thread, activeCount
from time import sleep
from sys import exit, exc_info

# Get a self-signed certificate
# openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout cert.pem

#
# Configuration
#
MAX_THREADS     = 50
BUFSIZE         = 2048
TIMEOUT_SOCKET  = 5
LOCAL_ADDR      = '0.0.0.0'
LOCAL_PORT      = 4443
CERTFILE        = 'cert.pem'
KEYFILE         = 'cert.pem'
EXIT            = False

#
# Error
#
def Error():
   exc_type, _, exc_tb = exc_info()
   print exc_type, exc_tb.tb_lineno

#
# Close Socket
#
def Close(sock):
   try:
      sock.close()
   except:
      None

#
# Proxy Loop
#
def Proxy_Loop(socket_src, socket_dst):
   while(not EXIT):
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
         s.bind((LOCAL_ADDR, LOCAL_PORT))
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
# Connection
#
def Connection(wrapper):
   dst = wrapper.recv(BUFSIZE)
   dst_addr = dst.split(':')[0]
   dst_port = int(dst.split(':')[1])
   socket_dst = Connect_To_Dst(dst_addr, dst_port)
   if socket_dst == 0:
      wrapper.send('0')
      return
   else:
      wrapper.send('1')
   Proxy_Loop(wrapper, socket_dst)
   if wrapper != 0:
      Close(wrapper)
   if socket_dst != 0:
      Close(socket_dst)

#
# Exit
#
def Exit_Handler(signal, frame):
   print 'EXIT'
   global EXIT
   EXIT = True
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
   while(not EXIT):
      if activeCount() < MAX_THREADS:
         # Accept
         try:
            wrapper, addr = new_socket.accept()
            wrapper = ssl.wrap_socket(
                        wrapper,
                        server_side = True,
                        certfile = CERTFILE,
                        keyfile = KEYFILE,
                        ssl_version = ssl.PROTOCOL_TLSv1
                    )
            wrapper.setblocking(1)
         except:
            Error()
            continue
         # Thread incoming connection
         recv_thread = Thread(target=Connection, args=(wrapper, ))
         recv_thread.start()
      else:
         sleep(3)
      # end while
   new_socket.close()

