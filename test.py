#!/usr/bin/python3

import sys

from ethernet.mac_address import MacAddress
from ethernet.ip4_address import Ip4Address
from ethernet.enc28j60 import Enc28j60
from ethernet.ethernet_frame import EthernetFrame


def log(message=""):
	print(message)
	sys.stdout.flush()


if __name__ == "__main__":
	mac_addr = MacAddress([0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
	ip_addr = Ip4Address([10, 0, 1, 254])
	filter_mac_address = MacAddress([0x30, 0x9c, 0x23, 0x0d, 0x2d, 0x7f])

	driver = Enc28j60(mac_addr)
	driver.initialize()
	log("ENC28J60 Revision {:d}".format(driver.revision))

	link_status = driver.is_link_up
	packet_number = 0

	while packet_number < 1000000:
		new_status = driver.is_link_up

		if link_status != new_status:
			link_status = new_status
			log("link status = {}".format(link_status))

		packet = driver.receive_packet()

		if len(packet) == 0:
			continue
		elif len(packet) >= 14:
			frame = EthernetFrame.from_buffer(packet)

			if frame.src_mac_address != filter_mac_address:
				continue

			if frame.type in (0x0800, 0x0806):
			# if frame.type == 0x0806:
				packet_number += 1
				log()
				log("#{:d}\n{}".format(packet_number, frame))

				if frame.type == 0x0800:	# IPv4
					if frame.payload.protocol == 1:
						if frame.payload.payload.type == 8:
							log("ICMP Request")
				if frame.type == 0x0806:	# ARP
					if frame.payload.tpa == ip_addr:
						print("ARP for my IP")
						new_packet = packet[6:12]
						new_packet.extend(bytes(mac_addr))
						new_packet.extend(packet[12:14])
						new_packet.extend(frame.payload.response(mac_addr))
						driver.send_packet(new_packet)
		else:
			log("possibly invalid packet: " + " ".join(["{:02x}".format(byte) for byte in packet]))

	log("done")
