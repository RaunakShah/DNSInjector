import sys
import getopt
import os
import scapy.all as scapy
import netifaces as ni

count = 0
hasher = {}
hostfile_dict = {}
def handle(packet):
	global count
	global hasher

	# Check if current packet is a DNS response
	if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.DNSRR):
		count+=1

		# Keys points of reference within a packet to detect poisoning attempts - source IP, destination IP, DNS ID, Queried name
 
		fields = str(packet.getlayer(scapy.IP).src)+ '+' + str(packet.getlayer(scapy.IP).dst) + '+' + str(packet.getlayer(scapy.DNS).id) + '+' + str(packet.getlayer(scapy.DNS).qd.qname)
		if fields in hasher.keys():
			if [packet.getlayer(scapy.DNSRR).rdata] != hasher[fields]:
				print("\nALERT - Possible DNS Poisoning attempt!")
				srcip, dstip, dnsid, qname = fields.split('+')
				print("TxID "+ dnsid + " Request for " + qname)
				print("Answer1: %s" % hasher[fields])
				print("Answer2: %s" % [packet.getlayer(scapy.DNSRR).rdata])

		else:
			i = packet.getlayer(scapy.DNS).ancount
			hasher[fields] = [packet.getlayer(scapy.DNSRR).rdata]
			i -= 1
			while i>0:
				hasher[fields].append(packet.getlayer(scapy.DNSRR)[i].rdata)
				i -= 1

		if count == 10:
		#	print("Renewing hash")
			hasher = {}
			count = 0	

	
def hostfile_parser(hostfile):
	host = dict()
	with open(hostfile, 'r') as file:
		for line in file:
			ip, sep, domain = line.partition(" ")
			host[ip] = domain
	return host
	
if __name__ == "__main__":
	cmdLineOptions = "i:r:"
	options, bpf  = getopt.getopt(sys.argv[1:], cmdLineOptions)
	dev = ni.gateways()['default'][ni.AF_INET][1]
	filter = " ".join(bpf)#+= str(bpf)
	for op in options:
		if "-i" in op[0]:
			dev = op[1]
			scapy.sniff(iface=dev, filter=filter, prn=handle)
		elif "-r" in op[0]:
			tracefile = op[1]
			scapy.sniff(offline = tracefile, filter = filter, prn = handle)



