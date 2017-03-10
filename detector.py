# Swetal Bhatt
# Simple IDS
# 	- prints out IPS that attempt 3x as many SYN's as SYNACK's received

import sys
import dpkt
import socket

syns = {}		# source IP addr: # of syn packets
synacks = {}	# dest IP addr: # of synack packets
badguys = []	# list of suspected port scan IPS

fname = str(sys.argv[1])
print "filename: ", fname

f = open(fname)
pcap = dpkt.pcap.Reader(f)
counter = 0

# For each packet in the pcap process the contents
print "reading pcap file..."
for timestamp, buf in pcap:
	counter += 1

	# Unpack the Ethernet frame (mac src/dst, ethertype)
	try:
		eth = dpkt.ethernet.Ethernet(buf)
	except:
		pass

	# Make sure the Ethernet data contains an IP packet
	if not isinstance(eth.data, dpkt.ip.IP):
		# print counter, ' Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
		continue

	# Now grab the data within the Ethernet frame (the IP packet)
	ip = eth.data

	# Check for TCP in the transport layer
	if isinstance(ip.data, dpkt.tcp.TCP):

		# Set the TCP data
		tcp = ip.data

		# now do something with tcp.flags
		syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
		ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0

		# count the number of syn and number of synacks

		if syn_flag == 1 and ack_flag == 0: # it is a syn packet
			# store the source address
			addr = socket.inet_ntoa(ip.src)
			# increment that address's syn count
			if addr in syns: syns[addr] = syns[addr] + 1
			else: syns[addr] = 1
	
		if syn_flag == 1 and ack_flag == 1: # it is a synack packet
			# store the destination address
			addr = socket.inet_ntoa(ip.dst)
			# increment the address's synack count
			if addr in synacks: synacks[addr] = synacks[addr] + 1
			else: synacks[addr] = 1

		# print counter, "; ", "SYN:", syn_flag, " ACK:", ack_flag

f.close()

print "finished reading pcap file."

# port scan condition
# syn_count >= (3 * synack_count)

# process syn and synacks to find suspected port scanners 
# update badguys list

for addr in syns:
	# the syn count for the given address
	syn_count = syns[addr]
	
	if addr in synacks:
		# the synack count for the given address
		synack_count = synacks[addr]

		print "addr: ", addr, " syns: ", syn_count, "synacks: ", synack_count

		# check condition
		if syn_count >= (3 * synack_count):
			# bad guy!
			badguys.append(addr)

	if addr not in synacks:
		print "addr: ", addr, " syns: ", syn_count, "synacks: ", 0
		if syn_count >= 3:
			badguys.append(addr)

# print list of suspected port scanners

print "SYN scan suspect attackers:"
for guy in badguys:
	print guy


