# https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Packet_structure

REPLY = 0x02

class ArpFrame:
    def __init__(self, buffer):
        self.htype = buffer[0] * 256 + buffer[1]
        self.ptype = buffer[2] * 256 + buffer[3]
        self.hlen = buffer[4]
        self.plen = buffer[5]
        self.oper = buffer[6] * 256 + buffer[7]
        pos = 8
        self.sha = ":".join('%02x' % buffer[pos+idx] for idx in range(self.hlen))
        pos += self.hlen
        self.spa = ".".join('%d' % buffer[pos+idx] for idx in range(self.plen))
        pos += self.plen
        self.tha = ":".join('%02x' % buffer[pos+idx] for idx in range(self.hlen))
        pos += self.hlen
        self.tpa = ".".join('%d' % buffer[pos+idx] for idx in range(self.plen))

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
            "sender hardware address = {}".format(self.sha),
            "sender protocol address = {}".format(self.spa),
            "target hardware address = {}".format(self.tha),
            "target protocol address = {}".format(self.tpa),
        ]

        return "\n".join(parts)
