# https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure

REPLY = 0x02

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
            sha=":".join("{:02x}".format(byte) for byte in buf[sha_pos:spa_pos]),
            spa=".".join("{:d}".format(byte) for byte in buf[spa_pos:tha_pos]),
            tha=":".join("{:02x}".format(byte) for byte in buf[tha_pos:tpa_pos]),
            tpa=".".join("{:d}".format(byte) for byte in buf[tpa_pos:tend_pos])
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

    def response(self, src_mac_addr):
        buffer = [
            (self.htype >> 8) & 0xFF, self.htype & 0xFF,
            (self.ptype >> 8) & 0xFF, self.ptype & 0xFF,
            self.hlen,
            self.plen,
            0, REPLY
        ]

        buffer.extend(src_mac_addr)
        buffer.extend([int(b) for b in self.tpa.split('.')])
        buffer.extend([int(b, 16) for b in self.sha.split(':')])
        buffer.extend([int(b) for b in self.spa.split('.')])
        buffer.extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

        return buffer

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
