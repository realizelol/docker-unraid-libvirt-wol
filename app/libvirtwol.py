#!/usr/bin/python3
#    LibVirt Wake On Lan
#    Copyright (C) 2012 Simon Cadman
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#    dmacias - added fixes for ether proto 0x0842

import sys
import socket
import struct
import string
import libvirt
import logging
from xml.dom import minidom
from pylibpcap.pcap import sniff, rpcap, wpcap

class LibVirtWakeOnLan:

    @staticmethod
    def StartServerByMACAddress(mac):
        conn = libvirt.open(None)
        if conn == None:
            logging.error('Failed to open connection to the hypervisor')
            sys.exit(1)

        domains = conn.listAllDomains()
        for domain in domains:
            domainName = domain.name()
            params = []
            # TODO - replace with api calls to fetch network interfaces
            xml = minidom.parseString(domain.XMLDesc(0))
            devices = xml.documentElement.getElementsByTagName("devices")
            for device in devices:
                for interface in device.getElementsByTagName("interface"):
                    macadd = interface.getElementsByTagName("mac")
                    foundmac = macadd[0].getAttribute("address")
                    if foundmac == mac:
                        logging.info("Waking up %s", domainName)
                        state = domain.state()[0]
                        if state == 3:
                            domain.resume()
                            logging.info("Resuming VM with MAC address %s", mac)
                            return True
                        elif state == 5:
                            domain.create()
                            logging.info("Creating VM with MAC address %s", mac)
                            return True
                        elif state == 7:
                            domain.pMWakeup()
                            logging.info("Waking hibernating VM with MAC address %s", mac)
                            return True
        logging.info("Didn't find a VM with MAC address %s", mac)
        return False

    @staticmethod
    def GetMACAddress(s):
            # added fix for ether proto 0x0842
            size = len(s)
            bytes = map(lambda x: '%.2x' % x, map(ord, s))
            counted = 0
            macpart = 0
            maccounted = 0
            macaddress = None
            newmac = ""

            for byte in bytes:
                if counted < 6:
                    # find 6 repetitions of 255 and added fix for ether proto 0x0842
                    if byte == "ff" or size < 110:
                        counted += 1
                else:
                    # find 16 repititions of 48 bit mac
                    macpart += 1
                    if newmac != "":
                        newmac += ":"

                    newmac += byte

                    if macpart == 6 and macaddress == None:
                        macaddress = newmac

                    if macpart == 6:
                        #if macaddress != newmac:
                            #return None
                        newmac = ""
                        macpart = 0
                        maccounted += 1

            if counted > 5 and maccounted > 5:
                return macaddress

    @staticmethod
    def DecodeIPPacket(s):
        if len(s) < 20:
            return None
        d = {}
        d['version'] = (ord(s[0]) & 0xf0) >> 4
        d['header_len'] = ord(s[0]) & 0x0f
        d['tos'] = ord(s[1])
        d['total_len'] = socket.ntohs(struct.unpack('H', s[2:4])[0])
        d['id'] = socket.ntohs(struct.unpack('H', s[4:6])[0])
        d['flags'] = (ord(s[6]) & 0xe0) >> 5
        d['fragment_offset'] = socket.ntohs(struct.unpack('H', s[6:8])[0] & 0x1f)
        d['ttl'] = ord(s[8])
        d['protocol'] = ord(s[9])
        d['checksum'] = socket.ntohs(struct.unpack('H', s[10:12])[0])
        d['source_address'] = pcap.ntoa(struct.unpack('i', s[12:16])[0])
        d['destination_address'] = pcap.ntoa(struct.unpack('i', s[16:20])[0])
        if d['header_len'] > 5:
            d['options'] = s[20:4 * (d['header_len'] - 5)]
        else:
            d['options'] = None
        d['data'] = s[4 * d['header_len']:]
        return d

    @staticmethod
    def InspectIPPacket(pktlen, data, timestamp):
        if not data:
            return
        decoded = LibVirtWakeOnLan.DecodeIPPacket(data[14:])
        macaddress = LibVirtWakeOnLan.GetMACAddress(decoded['data'])
        if not macaddress:
            return
        return LibVirtWakeOnLan.StartServerByMACAddress(macaddress)

def recv(port=9, addr="192.168.9.246", buf_size=1024):
    """recv([port[, addr[,buf_size]]]) - waits for a datagram and returns the data."""

    # Create the socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Set some options to make it multicast-friendly
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
            pass # Some systems don't support SO_REUSEPORT
    s.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_TTL, 20)
    s.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_LOOP, 1)

    # Bind to the port
    s.bind(('', port))

    # Set some more multicast options
    intf = socket.gethostbyname(socket.gethostname())
    s.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(intf))
    s.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(addr) + socket.inet_aton(intf))

    # Receive the data, then unregister multicast receive membership, then close the port
    data, sender_addr = s.recvfrom(buf_size)
    s.setsockopt(socket.SOL_IP, socket.IP_DROP_MEMBERSHIP, socket.inet_aton(addr) + socket.inet_aton('0.0.0.0'))
    s.close()
    return data

if __name__ == '__main__':
    from lvwolutils import Utils
    Utils.SetupLogging()

    # line below is replaced on commit
    LVWOLVersion = "20140814 231218"
    Utils.ShowVersion(LVWOLVersion)

    if len(sys.argv) < 2:
        print('usage: libvirtwol <interface>')
        sys.exit(0)

    interface = sys.argv[1]
#    p = pcap.pcapObject()
    # Get device informations if possible (IP address assigned)
#    try:
#        net, mask = pcap.lookupnet(interface)
#    except:
#        net, mask = "192.168.8.0", "255.255.254.0"
    # set promiscuous to 1 so all packets are captured
#    p.open_live(interface, 1600, 1, 100)
    # added support for ether proto 0x0842
#    p.setfilter('udp port 9 or ether proto 0x0842', 0, 0)
    netfilter = "udp port 9 or ether proto 0x0842"

    #pktlen, timestamp, data = sniff(interface, filters=netfilter, count=-1, promisc=1)
    #logging.info("received[plen]: %s", pktlen)
    #logging.info("received[t]: %s", timestamp)
    #logging.info("received[buf]: %s", data)
    #print("received[plen]: " + pktlen)
    #print("received[t]: " + timestamp)
    #print("received[buf]: " + data)
    #pdata = pktlen, data, timestamp

    pack = recv()
    while True:
        print(pack)
        logging("pack: %s", pack)
        try:
            LibVirtWakeOnLan.InspectIPPacket(pack)
        except KeyboardInterrupt:
            break
        except Exception:
            continue
