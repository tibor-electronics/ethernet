# https://en.wikipedia.org/wiki/User_Datagram_Protocol#Packet_structure

class UdpDatagram:
    def __init__(self, datagram):
        self.source_port = datagram[0] * 256 + datagram[1]
        self.destination_port = datagram[2] * 256 + datagram[3]
        self.length = datagram[4] * 256 + datagram[5]
        self.checksum = datagram[6] * 256 + datagram[7]

    def __repr__(self):
        parts = [
            "UDP",
            "src port = {}".format(self.source_port),
            "dst port = {}".format(self.destination_port),
            "length   = {}".format(self.length),
            "checksum = {}".format(self.checksum),
        ]

        return "\n  ".join(parts)
