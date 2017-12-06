#include <unistd.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* UDP header is always 8 bytes */
#define SIZE_UDP 8
/* ICMP header is always 8 bytes */
#define SIZE_ICMP 8


#define ARP_PACKET_TYPE 0x0806
#define IP_PACKET_TYPE 0x0800

/* Ethernet header */
struct sniff_ethernet {
	u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
	u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
	u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
	u_char  ip_tos;                 /* type of service */
	u_short ip_len;                 /* total length */
	u_short ip_id;                  /* identification */
	u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	u_char  ip_ttl;                 /* time to live */
	u_char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
	struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)


//UDP header
struct sniff_udp{
	u_short src_port;	/* source port */
	u_short dst_port;	/* source port */
	u_short len;		/* length */
	u_short checksum;
};

struct dns_header{
	u_short id;
	u_short flags;
	u_short qdcount;	/* number of entries in question	*/
	u_short ancount; 	/* number of resource records in answer */
	u_short nscount; 	/* number of name server resource records in authority records section */
	u_short arcount; 	/* number of resource records in additional records section */
	char data[0];
};

struct dns_question{
	u_char *question_section;
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
	void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;


	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf(" ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void dns_ques(struct dns_question *dns){

}
void dns_head(u_char* payload , int len){
	int i;
	u_char *d;
	struct dns_header *dns = (struct dns_header*)payload;
	printf("ID: %d\n", ntohs(dns->id));
	printf("%d\n", ntohs(dns->flags));
	printf("qd: %d\n", ntohs(dns->qdcount));
	printf("an: %hu\n", ntohs(dns->ancount));
	printf("ns: %hu\n", dns->nscount);
	printf("ar: %hu\n", dns->arcount);
//	d = (u_char *)(payload+(sizeof(struct dns_header)));
	printf("name:");
	for(i=0;i<sizeof(dns->data);i++)
		printf("%hu\n", ntohs(dns->data[i]));	
	printf("end");
//	exit(1);
}



	void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}



void printEthernetHeader(const struct sniff_ethernet *ethernet) {
	int i;
	for(i = 0;i<ETHER_ADDR_LEN;i++){
		printf("%02x",ethernet->ether_shost[i]);
		if(i!=5)
			printf(":");
	}
	printf(" -> ");

	for(i = 0;i<ETHER_ADDR_LEN;i++){
		printf("%02x",ethernet->ether_dhost[i]);
		if(i!=5)
			printf(":");
	}

	printf(" type %#06x",ntohs(ethernet->ether_type));
}

	void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct tm* timestamp;
	timestamp = localtime(&header->ts.tv_sec);
	char outstr[200];
	strftime(outstr, 200, "%F %T", timestamp); 
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	char * payload;                    /* Packet payload */
	const struct sniff_udp *udp;		/* UDP header */
	int size_ip;
	int size_payload;
	int size_udp;
	int len;
	int source_port;
	int destination_port;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	if(ntohs(ethernet->ether_type) == ARP_PACKET_TYPE){
		if(args != NULL){
			if(strstr((char *)(packet), (char *)(args))==NULL)
				return;
		}
		printEthernetHeader(ethernet);
		printf(" ARP \n");
		return;
	}
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		return;
	}

	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_UDP:
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);				
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_UDP);
			size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_UDP);
			if(args!=NULL)
				if(strstr((char *)(payload),(char *)( args))==NULL)
					return;
			//printf("Src Port: %d\n", ntohs(udp->src_port));
			printf("\n%s.%d ", outstr,header->ts.tv_usec);
			printEthernetHeader(ethernet);
			printf(" len %d\n", (ntohs(ip->ip_len)+SIZE_ETHERNET));
			printf("%s:%d -> ", inet_ntoa(ip->ip_src), ntohs(udp->src_port));
			printf("%s:%d ", inet_ntoa(ip->ip_dst), ntohs(udp->dst_port));
			//printf("Dst Port: %d\n", ntohs(udp->dst_port));					
			printf(" UDP\n");
			break;

		case IPPROTO_IP:
			//printf("   Protocol: IP\n");
			if(args!=NULL)
				if(strstr((char *)packet, (char*)(args))==NULL)
					return;
			printEthernetHeader(ethernet);
			printf("\n");
			break;
		default:
			if(args!=NULL)
				if(strstr((char *)(packet), (char *)(args))==NULL)
					return;
			printEthernetHeader(ethernet);
			printf("\n");
			return;
	}


	if (size_payload > 0) {
		dns_head(payload, size_payload);
		//print_payload(payload, size_payload);
	}	

	return;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char* filter_exp = NULL;		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 1000;			/* number of packets to capture */
	const char* fname = NULL;
	const char* search = NULL;
	if(argc>1){
		int op;		
		char *cmdLineOptions = "r:i:s:";
		while((op = getopt(argc, argv, cmdLineOptions)) != -1){
			switch (op){
				case 'i':
					dev = optarg;
					break; 				
				case 'r':
					fname = optarg;
					break;
				case 's':
					search = optarg;			
					break;
			}	
		} 
		if(argv[optind]!=NULL){
			filter_exp = argv[optind];
		}
	}

	if(fname == NULL){
		if(dev==NULL) {
			/* find a capture device if not specified on command-line */
			dev = pcap_lookupdev(errbuf);
			if (dev == NULL) {
				fprintf(stderr, "Couldn't find default device: %s\n",
						errbuf);
				exit(EXIT_FAILURE);
			}
		}

		/* get network number and mask associated with capture device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
					dev, errbuf);
			net = 0;
			mask = 0;
		}

		/* open capture device */
		handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	}
	else{
		handle = pcap_open_offline(fname, errbuf);
	}
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}


	/* compile the filter expression */
	if(filter_exp!=NULL){
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n",
					filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}

		/* apply the compiled filter */
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n",
					filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
	}
	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, search);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

	return 0;
}


