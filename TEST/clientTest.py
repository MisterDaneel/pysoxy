import SocksiPy as socks
ProxyAddr = "127.0.0.1"
ProxyPort = 5555
ProxyType = socks.PROXY_TYPE_SOCKS5
DstAddr   = "127.0.0.1"
DstPort   = 5556
try:
   socks.setdefaultproxy(ProxyType, ProxyAddr, ProxyPort, True)
   wrapper = socks.socksocket()
   wrapper.connect((DstAddr,DstPort))
   wrapper.sendall("HELLO")
   print wrapper.recv(2048)
   wrapper.sendall("AH AH AH")
   print wrapper.recv(2048)
   wrapper.close()
except Exception,e:
   print "ERROR:", e
   wrapper.close()
	
	
