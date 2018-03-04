# https://en.wikipedia.org/wiki/IPv4#Packet_structure

from ethernet.udp_datagram import UdpDatagram

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

    def __init__(self, buffer):
        self.version = buffer[0] >> 4 & 0x0F
        self.ihl = buffer[0] & 0x0F
        self.type_of_service = buffer[1]
        self.total_length = buffer[2] * 256 + buffer[3]
        self.id = buffer[4] * 255 + buffer[5]
        self.flags = buffer[6] >> 5 & 0x03
        self.fragment_offset = (buffer[6] & 0x3F) * 256 + buffer[7]
        self.ttl = buffer[8]
        self.protocol = buffer[9]
        self.header_checksum = buffer[10] * 256 + buffer[11]
        self.source_address = ".".join('%d' % buffer[12+idx] for idx in range(4))
        self.destination_address = ".".join('%d' % buffer[16+idx] for idx in range(4))
        # self.options = [buffer[20 + idx] for idx in range(self.__totalLength - 20)]

        payload = buffer[self.ihl << 2:self.total_length]

        if self.protocol == 17:
            self.payload = UdpDatagram(payload)
        else:
            self.payload = ",".join(["{:02x}".format(byte) for byte in payload])
        # padding

    def __repr__(self):
        if self.protocol in PROTOCOLS:
            protocol_str = PROTOCOLS[self.protocol]
        else:
            protocol_str = "{:d}".format(self.protocol)

        parts = [
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
            "src      = {}".format(self.source_address),
            "dst      = {}".format(self.destination_address),
            "payload  = {}".format(self.payload)
        ]

        return "\n".join(parts)
