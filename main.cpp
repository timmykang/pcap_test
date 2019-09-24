#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#define ETHER_ADDR_LEN 6
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

uint16_t my_ntohs(uint16_t n) {
	return ((n & 0xFF00) >> 8) | ((n & 0x00FF) << 8);
}

uint32_t my_ntohl(uint32_t n) {
	return ((n & 0xFF000000) >> 24) | ((n & 0x00FF0000) >> 8) | ((n & 0x0000FF00) << 8) | ((n & 0x000000FF) << 24);
}

void print_ip(u_long ip) {
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
}


/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	u_long ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
	struct sniff_ethernet *ethernet;
	struct sniff_ip *ip;
	struct sniff_tcp *tcp;
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
	
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
		int ip_size, tcp_size, data_size;
    int i, res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;	
		ethernet = (struct sniff_ethernet*)(packet);
		printf("src mac");
		for(i = 0; i < ETHER_ADDR_LEN; i++) {
			printf(" : %02x", ethernet -> ether_shost[i]);
		}
		printf("\ndst mac");
		for(i = 0; i < ETHER_ADDR_LEN; i++) {
			printf(" : %02x", ethernet -> ether_dhost[i]);
		}
		if(my_ntohs(ethernet -> ether_type) == 0x0800) {
			packet = packet + 14;
			ip = (struct sniff_ip*)(packet);
			printf("\nsrc ip : ");
			print_ip(ip -> ip_src);
			printf("dst ip : ");
			print_ip(ip -> ip_dst);
			if((ip -> ip_p) == 0x06) {
				ip_size = 4 * IP_HL(ip);
				packet = packet + ip_size;
				tcp = (struct sniff_tcp*)(packet);
				tcp_size = 4 * TH_OFF(tcp);
				printf("src port : %d\n", my_ntohs(tcp -> th_sport));
				printf("dst port : %d\n", my_ntohs(tcp -> th_dport));
				data_size = my_ntohs(ip -> ip_len) - (ip_size + tcp_size);
				if(data_size != 0) {
					packet = packet + tcp_size;
					for(i = 1; i <= MIN(32, data_size); i++) {
						printf("%02x ", packet[i-1]);
						if(i % 16 == 0)	printf("\n");
					}
				}
			}
		}
		printf("\n");
  }
  pcap_close(handle);
  return 0;
}
