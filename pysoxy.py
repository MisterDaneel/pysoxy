# -*- coding: utf-8 -*-
#
# Small Socks5 Proxy Server in Python (2.7)
# from https://github.com/MisterDaneel/
#

# Network
import socket
import select
from struct import pack, unpack
# System
from signal import signal, SIGINT, SIGTERM
from threading import Thread, activeCount
from time import sleep
from sys import exit, exc_info

#
# Configuration
#
MAX_THREADS = 200
BUFSIZE = 2048
TIMEOUT_SOCKET = 5
LOCAL_ADDR = '0.0.0.0'
LOCAL_PORT = 9050
EXIT = False

#
# Constants
#
'''Version of the protocol'''
# PROTOCOL VERSION 5
VER = '\x05'
'''Method constants'''
# '00' NO AUTHENTICATION REQUIRED
M_NOAUTH = '\x00'
# 'FF' NO ACCEPTABLE METHODS
M_NOTAVAILABLE = '\xff'
'''Command constants'''
# CONNECT '01'
CMD_CONNECT = '\x01'
'''Address type constants'''
# IP V4 address '01'
ATYP_IPV4 = '\x01'
# DOMAINNAME '03'
ATYP_DOMAINNAME = '\x03'


def Error():
    import sys
    exc_type, _, exc_tb = exc_info()
    print("{}, {}".format(exc_type, exc_tb.tb_lineno))


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
                    return
                elif sock is socket_dst:
                    socket_src.send(data)
                else:
                    socket_dst.send(data)
        except socket.error, e:
            print("Loop failed - Code: {}, Message: {}".format(str(e[0]), e[1]))
            return


def Connect_To_Dst(dst_addr, dst_port):
    try:
        s = Create_Socket()
        s.connect((dst_addr, dst_port))
        return s
    except socket.error, e:
        print("Failed to connect to DST - Code: {}, Message: {}".format(str(e[0]), e[1]))
        return 0
    except:
        Error()
        return 0


def Request_Client(wrapper):
    try:
        # Client Request
        # +----+-----+-------+------+----------+----------+
        # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        # +----+-----+-------+------+----------+----------+
        s5_request = wrapper.recv(BUFSIZE)
        # Check VER, CMD and RSV
        if (s5_request[0] != VER or
                s5_request[1] != CMD_CONNECT or
                s5_request[2] != '\x00'):
            return False
        # IPV4
        if s5_request[3] == ATYP_IPV4:
            dst_addr = socket.inet_ntoa(s5_request[4:-2])
            dst_port = unpack('>H', s5_request[8:len(s5_request)])[0]
        # DOMAIN NAME
        elif s5_request[3] == ATYP_DOMAINNAME:
            sz_domain_name = ord(s5_request[4])
            dst_addr = s5_request[5: 5 + sz_domain_name - len(s5_request)]
            port_to_unpack = s5_request[5 + sz_domain_name:len(s5_request)]
            dst_port = unpack('>H', port_to_unpack)[0]
        else:
            return False
        return (dst_addr, dst_port)
    except:
        if wrapper != 0:
            wrapper.close()
        Error()
    return False


def Request(wrapper):
    dst = Request_Client(wrapper)
    try:
        # Server Reply
        # +----+-----+-------+------+----------+----------+
        # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        # +----+-----+-------+------+----------+----------+
        REP = '\x07'
        BND = '\x00' + '\x00' + '\x00' + '\x00' + '\x00' + '\x00'
        if dst:
            socket_dst = Connect_To_Dst(dst[0], dst[1])
        if not dst or socket_dst == 0:
            REP = '\x01'
        else:
            REP = '\x00'
            BND = socket.inet_aton(socket_dst.getsockname()[0])
            BND += pack(">H", socket_dst.getsockname()[1])
        reply = VER + REP + '\x00' + ATYP_IPV4 + BND
        wrapper.sendall(reply)

        # start proxy
        if REP == '\x00':
            Proxy_Loop(wrapper, socket_dst)
        if wrapper != 0:
            wrapper.close()
        if socket_dst != 0:
            socket_dst.close()
    except:
        if wrapper != 0:
            wrapper.close()
        Error()
        return False


def Subnegotiation_Client(wrapper):
    # Client Version identifier/method selection message
    # +----+----------+----------+
    # |VER | NMETHODS | METHODS  |
    # +----+----------+----------+
    identification_packet = wrapper.recv(BUFSIZE)
    # VER field
    if (VER != identification_packet[0]):
        return M_NOTAVAILABLE
    # METHODS fields
    NMETHODS = ord(identification_packet[1])
    METHODS = identification_packet[2:]
    if (len(METHODS) != NMETHODS):
        return M_NOTAVAILABLE
    for METHOD in METHODS:
        if(METHOD == M_NOAUTH):
            return M_NOAUTH
    return M_NOTAVAILABLE


def Subnegotiation(wrapper):
    try:
        METHOD = Subnegotiation_Client(wrapper)
        # Server Method selection message
        # +----+--------+
        # |VER | METHOD |
        # +----+--------+
        reply = VER + METHOD
        wrapper.sendall(reply)
        if METHOD == M_NOAUTH:
            return True
    except:
        Error()
    return False


def Create_Socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT_SOCKET)
    except socket.error, e:
        print("Failed to create socket - Code: {}, Message: {}".format(str(e[0]), e[1]))
        return 0
    return s


def Bind_Port(s):
    # Bind
    try:
        print 'Bind', str(LOCAL_PORT)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((LOCAL_ADDR, LOCAL_PORT))
    except socket.error, e:
        print("Bind failed in server - Code: {}, Message: {}".format(str(e[0]), e[1]))
        s.close()
        return 0
    # Listen
    try:
        print("Listen")
        s.listen(10)
    except socket.error, e:
        print("Listen failed - Code: {}, Message: {}".format(str(e[0]), e[1]))
        s.close()
        return 0
    return s


def Exit_Handler(signal, frame):
    global EXIT
    EXIT = True
    exit(0)


if __name__ == '__main__':
    new_socket = Create_Socket()
    Bind_Port(new_socket)
    if not new_socket:
        print("Failed to create server")
        exit(0)
    signal(SIGINT, Exit_Handler)
    signal(SIGTERM, Exit_Handler)
    while(not EXIT):
        sessions = activeCount() - 1
        print("sessions: {}".format(sessions))
        if sessions < MAX_THREADS:
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
    new_socket.close()
