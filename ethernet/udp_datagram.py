# https://en.wikipedia.org/wiki/User_Datagram_Protocol#Packet_structure

class UdpDatagram:
    @classmethod
    def from_buffer(cls, buf):
        return cls(
           source_port=buf[0] * 256 + buf[1],
           destination_port=buf[2] * 256 + buf[3],
           length=buf[4] * 256 + buf[5],
           checksum=buf[6] * 256 + buf[7],
           payload=buf[8:]
        )


    def __init__(self, source_port=0, destination_port=0, length=0, checksum=0, payload=None):
        self.source_port = source_port
        self.destination_port = destination_port
        self.length = length
        self.checksum = checksum
        self.payload = payload


    def __repr__(self):
        parts = [
            "UDP",
            "src port = {}".format(self.source_port),
            "dst port = {}".format(self.destination_port),
            "length   = {}".format(self.length),
            "checksum = {}".format(self.checksum),
            "payload  = {}".format(self.payload)
        ]

        return "\n  ".join(parts)
