# -*- coding: utf-8 -*-
#
# Small Socks5 Proxy Server in Python
# from https://github.com/MisterDaneel/

# Network
import socket
import select
from struct import pack, unpack
# System
import threading
from time import sleep

# Logging
import logging
import coloredlogs


# Logging
LOGGER_BASENAME = '''pysoxy'''
LOGGER = logging.getLogger(LOGGER_BASENAME)

# Configuration
MAX_THREADS = 200
BUFSIZE = 2048
TIMEOUT_SOCKET = 5

# Constants
'''Version of the protocol'''
# PROTOCOL VERSION 5
VER = b'\x05'
'''Method constants'''
# '00' NO AUTHENTICATION REQUIRED
M_NOAUTH = b'\x00'
# 'FF' NO ACCEPTABLE METHODS
M_NOTAVAILABLE = b'\xff'
'''Command constants'''
# CONNECT '01'
CMD_CONNECT = b'\x01'
'''Address type constants'''
# IP V4 address '01'
ATYP_IPV4 = b'\x01'
# DOMAINNAME '03'
ATYP_DOMAINNAME = b'\x03'


class LoggerMixin:

    def __init__(self):
        logger_basename = '''pysoxy'''
        self._logger = logging.getLogger(f'{logger_basename}.{self.__class__.__name__}')


class ExitStatus:
    """Manage exit status."""
    def __init__(self):
        self.exit = False

    def set_status(self, status):
        """ set exist status """
        self.exit = status

    def get_status(self):
        """ get exit status """
        return self.exit


class Request(LoggerMixin):
    """________________."""

    def __init__(self,
                 wrapper,
                 local_addr_e):
        super().__init__()
        self.wrapper = wrapper
        self.local_addr_e = local_addr_e
        self.socket_src = None
        self.socket_dst = None

    def proxy_loop(self):
        """____<@Daneel, what does this method do?>___"""
        while not EXIT.get_status():
            try:
                reader, _, _ = select.select([self.wrapper, self.socket_dst], [], [], 1)
            except select.error as err:
                self._logger.debug('Select failed: %s', err)
                return
            if not reader:
                continue
            try:
                for sock in reader:
                    data = sock.recv(BUFSIZE)
                    if not data:
                        return
                    if sock is self.socket_dst:
                        self.wrapper.send(data)
                    else:
                        self.socket_dst.send(data)
            except socket.error as err:
                self._logger.debug('Loop failed: %s', err)
                return

    def request_client(self):
        """Returns the destination address and port found in the SOCKS request."""
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        try:
            s5_request = self.wrapper.recv(BUFSIZE)
        except ConnectionResetError:
            if self.wrapper != 0:
                self.wrapper.close()
            self._logger.debug("Error")
            return False
        # Check VER, CMD and RSV
        if (
                s5_request[0:1] != VER or
                s5_request[1:2] != CMD_CONNECT or
                s5_request[2:3] != b'\x00'
        ):
            return False
        # IPV4
        if s5_request[3:4] == ATYP_IPV4:
            dst_addr = socket.inet_ntoa(s5_request[4:-2])
            dst_port = unpack('>H', s5_request[8:len(s5_request)])[0]
        # DOMAIN NAME
        elif s5_request[3:4] == ATYP_DOMAINNAME:
            sz_domain_name = s5_request[4]
            dst_addr = s5_request[5: 5 + sz_domain_name - len(s5_request)]
            port_to_unpack = s5_request[5 + sz_domain_name:len(s5_request)]
            dst_port = unpack('>H', port_to_unpack)[0]
        else:
            return False
        return dst_addr, dst_port

    def request(self):
        """
            The SOCKS request information is sent by the client as soon as it has
            established a connection to the SOCKS server, and completed the
            authentication negotiations.  The server evaluates the request, and
            returns a reply
        """
        dst = self.request_client()
        # Server Reply
        # +----+-----+-------+------+----------+----------+
        # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        # +----+-----+-------+------+----------+----------+
        rep = b'\x07'
        bnd = b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00'
        if dst:
            ss = SocketServerExternal(dst[0], dst[1], self.local_addr_e)
            self.socket_dst = ss.connect_to_dst()
        if not dst or self.socket_dst == 0:
            rep = b'\x01'
        else:
            rep = b'\x00'
            bnd = socket.inet_aton(self.socket_dst.getsockname()[0])
            bnd += pack(">H", self.socket_dst.getsockname()[1])
        reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
        try:
            self.wrapper.sendall(reply)
        except socket.error:
            if self.wrapper != 0:
                self.wrapper.close()
            return
        # start proxy
        if rep == b'\x00':
            self.proxy_loop()
        if self.wrapper != 0:
            self.wrapper.close()
        if self.socket_dst != 0:
            self.socket_dst.close()


class Subnegotiation(LoggerMixin):
    """Performs handshake on version (or something)."""

    def __init__(self, wrapper):
        super().__init__()
        self.wrapper = wrapper

    def subnegotiation_client(self):
        """
            The client connects to the server, and sends a version
            identifier/method selection message
        """
        # Client Version identifier/method selection message
        # +----+----------+----------+
        # |VER | NMETHODS | METHODS  |
        # +----+----------+----------+
        try:
            identification_packet = self.wrapper.recv(BUFSIZE)
        except socket.error:
            self._logger.debug("Error")
            return M_NOTAVAILABLE
        # VER field
        if VER != identification_packet[0:1]:
            return M_NOTAVAILABLE
        # METHODS fields
        nmethods = identification_packet[1]
        methods = identification_packet[2:]
        if len(methods) != nmethods:
            return M_NOTAVAILABLE
        for method in methods:
            if method == ord(M_NOAUTH):
                return M_NOAUTH
        return M_NOTAVAILABLE

    def subnegotiation(self):
        """
            The client connects to the server, and sends a version
            identifier/method selection message
            The server selects from one of the methods given in METHODS, and
            sends a METHOD selection message
        """
        method = self.subnegotiation_client()
        # Server Method selection message
        # +----+--------+
        # |VER | METHOD |
        # +----+--------+
        if method != M_NOAUTH:
            return False
        reply = VER + method
        try:
            self.wrapper.sendall(reply)
        except socket.error:
            self._logger.debug("Error")
            return False
        return True


class SocketServerExternal(LoggerMixin):
    """Creates an INET, STREAMing socket for outgoing connections, *not* SOCKS encapsulated."""

    def __init__(self,
                 dst_addr,
                 dst_port,
                 local_addr_e):
        super().__init__()
        self.dst_addr = dst_addr
        self.dst_port = dst_port
        self.local_addr_e = local_addr_e

    def connect_to_dst(self):
        """Returns a connected remote socket at desired address (found in SOCKS request)"""
        sock = self._create_socket()
        if self.local_addr_e:
            try:
                self._logger.info("Local external address: %s", self.local_addr_e)
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    socket.AF_INET,
                    self.local_addr_e.encode()
                )
            except Exception as err:
                self._logger.info("Error: %s", err)
                EXIT.set_status(True)
        try:
            sock.connect((self.dst_addr, self.dst_port))
            self._logger.info("Destination address: %s:%s", self.dst_addr, self.dst_port)
            return sock
        except socket.error as err:
            self._logger.debug("Failed to connect to Destination")
            return 0

    def _create_socket(self):
        """ Creates an INET, STREAMing socket."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(TIMEOUT_SOCKET)
        except socket.error as err:
            self._logger.debug("Failed to create socket", err)
            SystemExit(0)
        return self.sock


class SocketServerInternal(LoggerMixin):
    """Creates an INET, STREAMing socket for incoming connections, SOCKS encapsulated."""

    def __init__(self,
                 local_addr,
                 local_port):
        super().__init__()
        self.sock = None
        self.local_addr = local_addr
        self.local_port = local_port

    def create_socket_and_listen(self):
        self._create_socket()
        self._bind()
        self._listen()

    def _create_socket(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(TIMEOUT_SOCKET)
        except socket.error as err:
            self._logger.debug("Failed to create socket", err)
            SystemExit(0)

    def _bind(self):
        try:
            self._logger.info("Local interal address: %s:%s", self.local_addr, str(self.local_port))
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.local_addr, self.local_port))
        except socket.error as err:
            self._logger.debug("Bind failed %s", err)
            self.sock.close()
            SystemExit(0)

    def _listen(self):
        try:
            self.sock.listen(10)
        except socket.error as err:
            self._logger.debug("Listen failed", err)
            self.sock.close()
            SystemExit(0)
        return self.sock


def connection(wrapper, local_addr_e):
    """Identifies SOCKS request and sets up connection to destination."""
    subnegotiation = Subnegotiation(wrapper)
    if subnegotiation.subnegotiation():
        request = Request(wrapper, local_addr_e)
        request.request()


class Proxy(LoggerMixin):

    def __init__(self, local_addr_i, local_port, local_addr_e=None):
        super().__init__()
        self.local_addr_i = local_addr_i
        self.local_port = local_port
        self.local_addr_e = local_addr_e
        self.new_socket = None
        self.thread = None
        self.terminate = False

    def start(self):
        self.new_socket = SocketServerInternal(self.local_addr_i, self.local_port)
        self.new_socket.create_socket_and_listen()
        self.thread = threading.Thread(target=self._execution)
        self.thread.start()

    def stop(self):
        EXIT.set_status(True)

    def _execution(self):
        while not EXIT.get_status():
            if threading.activeCount() > MAX_THREADS:
                sleep(3)
                continue
            try:
                conn, addr = self.new_socket.sock.accept()
                conn.setblocking(True)  # 1 == True and 0 == False
            except socket.timeout as e:
                # @Daneel, could you please explain why this exception happens and how this can be mitigated?
                continue
            recv_thread = threading.Thread(target=connection, args=(conn, self.local_addr_e))
            recv_thread.start()
        self._logger.info("Closing socket...")
        self.new_socket.sock.close()


if __name__ == '__main__':
    EXIT = ExitStatus()
    coloredlogs.install(level='INFO')
    # proxy = Proxy('10.10.1.72', 8080, '10.10.2.82')
    proxy = Proxy('127.0.0.1', 8080, '127.0.0.1')
    try:
        proxy.start()
        while True:
            pass
    except KeyboardInterrupt:
        proxy.stop()
