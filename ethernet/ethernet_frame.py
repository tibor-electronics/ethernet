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
		return cls(
			dst_mac_addr=MacAddress(buf[0:6]),
			src_mac_addr=MacAddress(buf[6:12]),
			type=buf[12] * 256 + buf[13],
			payload=buf[14:]
		)


	def __init__(self, dst_mac_addr, src_mac_addr, type, payload):
		self.dst_mac_address = dst_mac_addr
		self.src_mac_address = src_mac_addr
		self.type = type

		# if type >= 0x0600:
		if type == 0x0800:
			self.payload = IpFrame.from_buffer(payload)
		elif type == 0x0806:
			self.payload = ArpFrame.from_buffer(payload)
		else:
			self.payload = ",".join(["{:02x}".format(byte) for byte in payload])


	def __repr__(self):
		parts = [
			"dst mac = {}".format(self.dst_mac_address),
			"src mac = {}".format(self.src_mac_address),
			"type    = {}".format(self.type),
			"payload = {}".format(self.payload),
		]

		return "\n".join(parts)
