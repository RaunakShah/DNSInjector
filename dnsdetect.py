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
	if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.DNSRR):
		print("So far")
		count+=1 
		print(count)
		#print(packet.getlayer(scapy.IP).src) 
		#print(packet.getlayer(scapy.IP).dst+packet.getlayer(scapy.DNS).id) 
		#print(packet.getlayer(scapy.DNS).qd.qname)
		
		fields = str(packet.getlayer(scapy.IP).src)+ '+' + str(packet.getlayer(scapy.IP).dst) + '+' + str(packet.getlayer(scapy.DNS).id) + '+' + str(packet.getlayer(scapy.DNS).qd.qname)
		if fields in hasher.keys():
			if [packet.getlayer(scapy.DNSRR).rdata] != hasher[fields]:
				print("ALERT")
				srcip, dstip, dnsid, qname = fields.split('+')
				print("ID "+ dnsid + "request" + qname)
				print("Answer1 ")
				print(hasher[fields])
				print("Answer2 ")
				print([packet.getlayer(scapy.DNSRR).rdata])

				print(fields)
		else:
			i = packet.getlayer(scapy.DNS).ancount
			hasher[fields] = [packet.getlayer(scapy.DNSRR).rdata]
			i -= 1
			while i>0:
				hasher[fields].append(packet.getlayer(scapy.DNSRR)[i].rdata)
				i -= 1
		if count == 10:
			print("Renewing hash")
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
	filter = "port 53 " 
	if bpf:
		filter += str(bpf)
	print(str(hostfile_dict))
	for op in options:
		if "-i" in op[0]:
			dev = op[1]
			scapy.sniff(iface=dev, filter=filter, prn=handle)
		elif "-r" in op[0]:
			tracefile = op[1]
			scapy.sniff(offline = tracefile, filter = filter, prn = handle)



