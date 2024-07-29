#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "pcap-test.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

bool is_tcp(const u_char* packet) {
    // check if packet is TCP
    // return true if it is TCP, false otherwise
    struct eth_header* eth = (struct eth_header*)packet;
    if (ntohs(eth->type) == 0x0800) { // IP protocol
        struct ip_header* ip = (struct ip_header*)(packet + sizeof(struct eth_header));
        if (ip->ip_p == 6) { // TCP protocol
            return true;
        }
    }
    return false;  
}

void tcp_analyze(const u_char* packet, const struct pcap_pkthdr* header) {
    // print following information
    // src mac / dst mac of ethernet header
    // src ip / dst ip of IP Header
    // src port / dst port of TCP header
    // payload of TCP
    struct eth_header* eth = (struct eth_header*)packet;
    struct ip_header* ip = (struct ip_header*)(packet + sizeof(struct eth_header));
    struct tcp_header* tcp = (struct tcp_header*)(packet + sizeof(struct eth_header) + (ip->ip_vhl & 0x0F) * 4);
    const u_char* payload_data = packet + sizeof(struct eth_header) + (ip->ip_vhl & 0x0F) * 4 + (tcp->tcp_offx2 >> 4) * 4;

    printf("Ethernet Header\n");
    printf("   |-Source MAC Address      : %02x:%02x:%02x:%02x:%02x:%02x \n",
           eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
           eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);
    printf("   |-Destination MAC Address : %02x:%02x:%02x:%02x:%02x:%02x \n",
           eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2],
           eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5]);

    printf("IP Header\n");
    printf("   |-Source IP Address       : %d.%d.%d.%d\n",
           ip->ip_src[0], ip->ip_src[1], ip->ip_src[2], ip->ip_src[3]);
    printf("   |-Destination IP Address  : %d.%d.%d.%d\n",
           ip->ip_dst[0], ip->ip_dst[1], ip->ip_dst[2], ip->ip_dst[3]);

    printf("TCP Header\n");
    printf("   |-Source Port             : %d\n", ntohs(tcp->tcp_src));
    printf("   |-Destination Port        : %d\n", ntohs(tcp->tcp_dst));

    struct payload payload;
    memset(&payload, 0, sizeof(payload));
    int payload_length = header->caplen - (payload_data - packet);
    if (payload_length > 20) payload_length = 20;
    memcpy(payload.data, payload_data, payload_length);

    printf("Data Payload\n");
    printf("   |-Payload (first 20 bytes): ");
    for (int i = 0; i < payload_length; i++) {
        printf("%02x ", payload.data[i]);
    }
    
    printf("\n\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		// printf("%u bytes captured\n", header->caplen);

        if( is_tcp(packet) ){
            tcp_analyze(packet, header);
        }
	}

	pcap_close(pcap);
}
