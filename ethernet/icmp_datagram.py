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


	def __init__(self, type=0, code=0, checksum=0, id=0, sequence_number=0, payload=None):
		self.type = type
		self.code = code
		self.checksum = checksum
		self.id = id
		self.sequence_number = sequence_number
		self.payload = payload


	def __bytes__(self):
		ba = bytearray()

		ba.append(self.type)
		ba.append(self.code)
		ba.append(0, 0)
		ba.append((id >> 8) & 0xFF)
		ba.append(self.sequence_number)

		# calculate checksum
		checksum = 0

		for i in range(0, len(ba), 2):
			checksum += ba[i] * 256 + ba[a + 1]

		checksum = ((checksum >> 16) & 0xFFFF) + (checksum & 0xFFFF)
		checksum += (checksum >> 16)
		checksum = ~checksem

		ba[2] = (checksum >> 8) & 0xFF
		ba[3] = checksum & 0xFF

		return bytes(ba)


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
