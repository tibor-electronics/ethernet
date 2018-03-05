# https://en.wikipedia.org/wiki/Ethernet_frame#Structure

from ethernet.mac_address import MacAddress
from ethernet.ip_frame import IpFrame
from ethernet.arp_frame import ArpFrame

# https://en.wikipedia.org/wiki/EtherType

# TYPES = {
# 	0x0800: "IPv4",
# 	0x0806: "ARP",
# 	0x86DD: "IPv6"
# 	0x8100: "802.1Q"
# 	0x809B: "AppleTalk"
# 	0x80F3: "AARP"
# }

# Layer 2 ethernet frame

class EthernetFrame(object):
	@classmethod
	def from_buffer(cls, buf):
		type=buf[12] * 256 + buf[13]

		# if type >= 0x0600:
		if type == 0x0800:
			payload = IpFrame.from_buffer(buf[14:])
		elif type == 0x0806:
			payload = ArpFrame.from_buffer(buf[14:])
		else:
			payload = buf[14:]

		return cls(
			dst_mac_addr=MacAddress(buf[0:6]),
			src_mac_addr=MacAddress(buf[6:12]),
			type=type,
			payload=payload
		)


	def __init__(self, dst_mac_addr, src_mac_addr, type, payload):
		self.dst_mac_address = dst_mac_addr
		self.src_mac_address = src_mac_addr
		self.type = type
		self.payload = payload


	def __bytes__(self):
		ba = bytearray()

		ba.extend(bytes(self.dst_mac_address))
		ba.extend(bytes(self.src_mac_address))
		ba.append((self.type >> 8) & 0xFF)
		ba.append(self.type & 0xFF)
		ba.extend(bytes(self.payload))

		return bytes(ba)


	def __repr__(self):
		parts = [
			"dst mac = {}".format(self.dst_mac_address),
			"src mac = {}".format(self.src_mac_address),
			"type    = {}".format(self.type),
			"payload = {}".format(self.payload),
		]

		return "\n".join(parts)
