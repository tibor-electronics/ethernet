#!/usr/bin/python3

import sys
from time import sleep

from ethernet.mac_address import MacAddress
from ethernet.ip4_address import Ip4Address
from ethernet.enc28j60 import Enc28j60
from ethernet.ethernet_frame import EthernetFrame
from ethernet.arp_frame import ArpFrame
from ethernet.icmp_datagram import IcmpDatagram


def log(message=""):
	print(message)
	sys.stdout.flush()


if __name__ == "__main__":
	mac_addr = MacAddress([0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
	ip_addr = Ip4Address([10, 0, 1, 254])
	filter_mac_address = None  # MacAddress([0x30, 0x9c, 0x23, 0x0d, 0x2d, 0x7f])

	driver = Enc28j60(mac_addr)
	driver.initialize()
	log("ENC28J60 Revision {:d}".format(driver.revision))

	packet_number = 0

	while True:
		if not driver.is_link_up:
			log("link down. Trying again in 1 second")
			sleep(1)
			continue

		packet = driver.receive_packet()

		if len(packet) == 0:
			continue
		elif len(packet) >= 14:
			frame = EthernetFrame.from_buffer(packet)

			if filter_mac_address is not None and frame.src_mac_address != filter_mac_address:
				continue

			if frame.type in (0x0800, 0x0806):
			# if frame.type == 0x0806:
				packet_number += 1
				log()

				if frame.type == 0x0800:	# IPv4
					if frame.payload.protocol == 1:
						if frame.payload.payload.type == 8:
							log("ICMP Request")
							current_datagram = frame.payload.payload
							new_datagram = IcmpDatagram()
							new_datagram.id = current_datagram.id
							new_datagram.sequence_number = current_datagram.sequence_number
							# build ip frame
							# build ethernet frame
							# send frame
				elif frame.type == 0x0806:	# ARP
					if frame.payload.tpa == ip_addr:
						print("ARP for my IP")
						new_arp_frame = ArpFrame.from_arp_frame(frame.payload)
						new_arp_frame.tha = new_arp_frame.sha
						new_arp_frame.tpi = new_arp_frame.spa
						new_arp_frame.sha = driver.mac_address
						new_arp_frame.spa = ip_addr
						log(new_arp_frame)
						new_frame = EthernetFrame(frame.src_mac_address, driver.mac_address, 0x0806, new_arp_frame)
						driver.send_packet(bytes(new_frame))
				
				log("#{:d}\n{}".format(packet_number, frame))
		else:
			log("possibly invalid packet: " + " ".join(["{:02x}".format(byte) for byte in packet]))

	log("done")
