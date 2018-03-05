# https://en.wikipedia.org/wiki/IPv4#Packet_structure

from ethernet.ip4_address import Ip4Address
from ethernet.udp_datagram import UdpDatagram
from ethernet.icmp_datagram import IcmpDatagram

# https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers

PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "ENCAP",
    89: "OSPF",
    132: "SCTP"
}

class IpFrame(object):
    @classmethod
    def from_buffer(cls, buf):
        ihl = buf[0] & 0x0F
        total_length = buf[2] * 256 + buf[3]
        protocol = buf[9]

        if protocol == 1:
            payload = IcmpDatagram.from_buffer(buf[ihl << 2:total_length])
        elif protocol == 17:
            payload = UdpDatagram.from_buffer(buf[ihl << 2:total_length])
        else:
            payload = buf[ihl << 2:total_length]

        return cls(
            version=buf[0] >> 4 & 0x0F,
            ihl=ihl,
            type_of_service=buf[1],
            total_length=total_length,
            id=buf[4] * 255 + buf[5],
            flags=buf[6] >> 5 & 0x03,
            fragment_offset=(buf[6] & 0x3F) * 256 + buf[7],
            ttl=buf[8],
            protocol=protocol,
            header_checksum=buf[10] * 256 + buf[11],
            source_address=Ip4Address(buf[12:16]),
            destination_address=Ip4Address(buf[16:20]),
            payload=payload
        )


    def from_ip_frame(cls, frame):
        return cls(
            version=frame.version,
            ihl=frame.ihl,
            type_of_service=frame.type_of_service,
            total_length=frame.total_length,
            id=frame.id,
            flags=frame.flags,
            fragment_offset=frame.fragment_offset,
            ttl=frame.ttl,
            protocol=frame.protocol,
            header_checksum=frame.header_checksum,
            source_address=frame.source_address,
            destination_address=frame.destination_address,
            payload=frame.payload
        )


    def __init__(self, version=0, ihl=0, type_of_service=0, total_length=0, \
            id=0, flags=0, fragment_offset=0, ttl=0, protocol=0, header_checksum=0, \
            source_address="0.0.0.0", destination_address="0.0.0.0", payload=None):
        self.version = version
        self.ihl = ihl
        self.type_of_service = type_of_service
        self.total_length = total_length
        self.id = id
        self.flags = flags
        self.fragment_offset = fragment_offset
        self.ttl = ttl
        self.protocol = protocol
        self.header_checksum = header_checksum
        self.source_address = source_address
        self.destination_address = destination_address
        # self.options = [buffer[20 + idx] for idx in range(self.__totalLength - 20)]
        self.payload = payload


    def __bytes__(self):
        ba = bytearray()

        ba.append(self.version << 4 | self.ihl)
        ba.append(self.type_of_service)
        ba.append((self.total_length >> 8) & 0xFF)
        ba.append(self.total_length & 0xFF)
        ba.append((self.id >> 8) & 0xFF)
        ba.append(self.id & 0xFF)
        ba.append(((self.flag << 5) & 0xC0) | (self.fragment_offset >> 8) & 0x3F)
        ba.append(self.fragment_offset & 0xFF)
        ba.append(self.ttl)
        ba.append(self.protocol)
        ba.append((self.header_checksum >> 8) & 0xFF)
        ba.append(self.header_checksum & 0xFF)
        ba.extend(bytes(self.source_address))
        ba.extend(bytes(self.destination_address))
        ba.extend(bytes(self.payload))

        return bytes(ba)


    def __repr__(self):
        if self.protocol in PROTOCOLS:
            protocol_str = PROTOCOLS[self.protocol]
        else:
            protocol_str = "{:d}".format(self.protocol)

        parts = [
            "IP",
            "version  = {}".format(self.version),
            "ihl      = {}".format(self.ihl),
            "service  = {}".format(self.type_of_service),
            "length   = {}".format(self.total_length),
            "id       = {}".format(self.id),
            "flags    = {}".format(self.flags),
            "offset   = {}".format(self.fragment_offset),
            "ttl      = {}".format(self.ttl),
            "protocol = {}".format(protocol_str),
            "checksum = {}".format(self.header_checksum),
            "src addr = {}".format(self.source_address),
            "dst addr = {}".format(self.destination_address),
            "payload  = {}".format(self.payload)
        ]

        return "\n".join(parts)
