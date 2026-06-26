#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN 6

/* Ethernet Header */
struct libnet_ethernet_hdr {
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

/* IP Header */
struct libnet_ipv4_hdr {
    u_int8_t  ip_hl:4, ip_v:4;            /* header length, version */
    u_int8_t  ip_tos;                     /* type of service */
    u_int16_t ip_len;                     /* total length */
    u_int16_t ip_id;                      /* identification */
    u_int16_t ip_off;                     /* fragment offset field */
    u_int8_t  ip_ttl;                     /* time to live */
    u_int8_t  ip_p;                       /* protocol */
    u_int16_t ip_sum;                     /* checksum */
    struct in_addr ip_src, ip_dst;        /* source and dest address */
};

/* TCP Header */
struct libnet_tcp_hdr {
    u_int16_t th_sport;                   /* source port */
    u_int16_t th_dport;                   /* destination port */
    u_int32_t th_seq;                     /* sequence number */
    u_int32_t th_ack;                     /* acknowledgement number */
    u_int8_t  th_x2:4, th_off:4;          /* data offset, rsvd */
    u_int8_t  th_flags;
    u_int16_t th_win;                     /* window */
    u_int16_t th_sum;                     /* checksum */
    u_int16_t th_urp;                     /* urgent pointer */
};

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    
   
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        // pcap_next_ex를 사용하여 패킷 캡처
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        // 1. Ethernet Header 파싱
        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        
        // IPv4 패킷(0x0800)인 경우에만 한 단계 더 진입
        if (ntohs(eth_hdr->ether_type) != 0x0800) continue;

        // 2. IP Header 파싱 (Ethernet 헤더 크기인 14바이트 뒤 세그먼트)
        struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + 14);
        
        // TCP 패킷(6)인 경우에만 정보 출력 수행
        if (ip_hdr->ip_p != 6) continue;

        // 3. TCP Header 파싱 (IP 헤더 길이 계산: ip_hl * 4)
        int ip_hdr_len = ip_hdr->ip_hl * 4;
        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + 14 + ip_hdr_len);

        // 4. Payload (Data) 위치 및 크기 계산
        int tcp_hdr_len = tcp_hdr->th_off * 4;
        int total_header_len = 14 + ip_hdr_len + tcp_hdr_len;
        int payload_len = ntohs(ip_hdr->ip_len) - (ip_hdr_len + tcp_hdr_len);
        const u_char* payload = packet + total_header_len;

        // --- 출력부 ---
        printf("\n========================================\n");
        printf("[★ TCP Packet Captured ★]\n");
        
        // Ethernet 정보 출력
        printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
               eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
        printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
               eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

        // IP 정보 출력
        printf("Src IP : %s\n", inet_ntoa(ip_hdr->ip_src));
        printf("Dst IP : %s\n", inet_ntoa(ip_hdr->ip_dst));

        // Port 정보 출력 (Network Byte Order 주의하여 ntohs 사용)
        printf("Src Port: %d\n", ntohs(tcp_hdr->th_sport));
        printf("Dst Port: %d\n", ntohs(tcp_hdr->th_dport));

        // Payload (Hexadecimal 최대 20바이트) 출력
        printf("Payload (Max 20B): ");
        int print_len = (payload_len > 20) ? 20 : payload_len;
        if (print_len <= 0) {
            printf("(No Data)");
        } else {
            for (int i = 0; i < print_len; i++) {
                printf("%02x ", payload[i]);
            }
        }
        printf("\n========================================\n");
    }

    pcap_close(handle);
    return 0;
}
