#!/usr/bin/env python
# -*-coding:utf-8 -*-

'''
| author: demo@echo.com
| date: 08/24/2018
| desc: UDP tools
| version: 0.1
'''

import socket
import os
import ctypes
import struct
import time
import threading
import netaddr

class ColorTxt:
    imp = '\033[1;33m[!]\033[1;m '
    err = '\033[1;35m[*]\033[1;m '
    que = '\033[1;34m[?]\033[1;m '
    ski = '\033[1;31m[-]\033[1;m '
    tar = '\033[1;32m[+]\033[1;m '
    run = '\033[1;36m[~]\033[1;m '

class IP(ctypes.Structure):
    _fields_ = [
        ('ihl', ctypes.c_ubyte, 4),
        ('ver', ctypes.c_ubyte, 4),
        ('tos', ctypes.c_ubyte),
        ('len', ctypes.c_ushort),
        ('id', ctypes.c_ushort),
        ('offset', ctypes.c_ushort),
        ('ttl', ctypes.c_ubyte),
        ('pro', ctypes.c_ubyte),
        ('sum', ctypes.c_ushort),
        ('src', ctypes.c_uint),
        ('dst', ctypes.c_uint),
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
        self.src_addr = socket.inet_ntoa(struct.pack("<L",self.src))
        self.dst_addr = socket.inet_ntoa(struct.pack("<L",self.dst))
        self.ihlen = self.ihl * 4

        try:
            self.protocol = self.protocol_map[self.pro]
        except Exception as e:
            self.protocol = str(self.pro)

class ICMP(ctypes.Structure):
    _fields_ = [
        ('type', ctypes.c_ubyte),
        ('code', ctypes.c_ubyte),
        ('sum', ctypes.c_ushort),
        ('id', ctypes.c_ushort),
        ('seq', ctypes.c_ushort),
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass

SUBNET = '192.168.1.0/24'
MSG = 'hello'.encode(encoding='utf-8')
MSGE = b'\x00\x00\r\x00\x00'

def udp_sender(SUBNET, MSG):
    time.sleep(2)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for ip in netaddr.IPNetwork(SUBNET):
        try:
            sender.sendto(MSG, ("%s" % ip, 32000))
        except:
            pass

def main():
    if os.name=='nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    host = socket.gethostbyname(socket.gethostname())

    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    t = threading.Thread(target = udp_sender, args = (SUBNET, MSG))
    t.start()

    try:
        while 1:
            raw_buffer = sniffer.recvfrom(65565)[0]
            ip_header = IP(raw_buffer)

            buf = raw_buffer[ip_header.ihlen:ip_header.ihlen + ctypes.sizeof(ICMP)]
            icmp_header = ICMP(buf)
            # print ("[*] Received -> Protocol:%s, Source:%s, TTL:%d, Type:%d, Code:%d" % (ip_header.protocol, ip_header.src_addr, ip_header.ttl, icmp_header.type, icmp_header.code))
            if icmp_header.code == 3 and icmp_header.type == 3:
                if netaddr.IPAddress(ip_header.src_addr) in netaddr.IPNetwork(SUBNET):
                    if raw_buffer[len(raw_buffer) - len(MSG):] == MSG:
                        print ('%s%s is up' %  (ColorTxt.tar, ip_header.src_addr))
                    elif raw_buffer[len(raw_buffer) - len(MSG):] == MSGE:
                        print ('%s%s appears to be up' %  (ColorTxt.tar, ip_header.src_addr))
                    else:
                        # print(raw_buffer[len(raw_buffer) - len(MSG):])
                        pass
    except KeyboardInterrupt as e:
        print(ColorTxt.err, 'Quit')
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


if __name__ == '__main__':
    main()
