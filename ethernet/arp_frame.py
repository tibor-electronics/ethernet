# https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure

REPLY = 0x02
from ethernet.mac_address import MacAddress
from ethernet.ip4_address import Ip4Address


class ArpFrame:
    @classmethod
    def from_buffer(cls, buf):
        hlen = buf[4]
        plen=buf[5]
        sha_pos = 8
        spa_pos = sha_pos + hlen
        tha_pos = spa_pos + plen
        tpa_pos = tha_pos + hlen
        tend_pos = tpa_pos + plen

        return cls(
            htype=buf[0] * 256 + buf[1],
            ptype=buf[2] * 256 + buf[3],
            hlen=hlen,
            plen=plen,
            oper=buf[6] * 256 + buf[7],
            sha=MacAddress(buf[sha_pos:spa_pos]),
            spa=Ip4Address(buf[spa_pos:tha_pos]),
            tha=MacAddress(buf[tha_pos:tpa_pos]),
            tpa=Ip4Address(buf[tpa_pos:tend_pos])
        )

    @classmethod
    def from_arp_frame(cls, frame):
        return cls(
            htype=frame.htype,
            ptype=frame.ptype,
            hlen=frame.hlen,
            plen=frame.plen,
            oper=frame.oper,
            sha=frame.sha,
            spa=frame.spa,
            tha=frame.tha,
            tpa=frame.tpa
        )


    def __init__(self, htype=0, ptype=0, hlen=0, plen=0, oper=0, sha=None, spa=None, tha=None, tpa=None):
        self.htype = htype
        self.ptype = ptype
        self.hlen = hlen
        self.plen = plen
        self.oper = oper
        self.sha = sha
        self.spa = spa
        self.tha = tha
        self.tpa = tpa

    def __bytes__(self):
        ba = bytearray()

        ba.append((self.htype >> 8) & 0xFF)
        ba.append(self.htype & 0xFF)
        ba.append((self.ptype >> 8) & 0xFF)
        ba.append(self.ptype & 0xFF)
        ba.append(self.hlen)
        ba.append(self.plen)
        ba.append(0)
        ba.append(REPLY)

        ba.extend(bytes(self.sha))
        ba.extend(bytes(self.spa))
        ba.extend(bytes(self.tha))
        ba.extend(bytes(self.tpa))
        ba.extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

        return bytes(ba)

    def __repr__(self):
        parts = [
            "ARP",
            "htype                   = {}".format(self.htype),
            "ptype                   = {}".format(self.ptype),
            "oper                    = {}".format(self.oper),
            "sender hardware address = {}".format(self.sha),
            "sender protocol address = {}".format(self.spa),
            "target hardware address = {}".format(self.tha),
            "target protocol address = {}".format(self.tpa),
        ]

        return "\n".join(parts)
