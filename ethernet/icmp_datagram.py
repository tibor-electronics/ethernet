# https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Datagram_structure
# https://en.wikipedia.org/wiki/Ping_(networking_utility)#Echo_request

TYPE_IPV4 = 8
TYPE_IPV6 = 128

class IcmpDatagram(object):
	@classmethod
	def from_buffer(cls, buf):
		return cls(
			type=buf[0],
			code=buf[1],
			checksum=buf[2] * 256 + buf[3],
			id=buf[4] * 256 + buf[5],
			sequence_number = buf[6] * 256 + buf[7],
			payload=buf[8:]
		)


	def __init__(self, type=TYPE_IPV4, code=0, checksum=0, id=0, sequence_number=0, payload=None):
		self.type = type
		self.code = code
		self.checksum = checksum
		self.id = id
		self.sequence_number = sequence_number
		self.payload = payload


	def __repr__(self):
		parts = [
			"ICMP",
			"type = {}".format(self.type),
			"code = {}".format(self.code),
			"checksum = {}".format(self.checksum),
			"id = {}".format(self.id),
			"sequence number = {}".format(self.sequence_number),
			"payload = {}".format(",".join(["{:02x}".format(byte) for byte in self.payload])),
		]

		return "\n".join(parts)
