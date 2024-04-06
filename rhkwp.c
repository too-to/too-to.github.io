#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// Ethernet Header 출력 함수
void printEthernetHeader(const struct ether_header *eth_header) {
    printf("Ethernet Header\n");
    printf("    Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
           eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("    Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
           eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
}

// IP Header 출력 함수
void printIPHeader(const struct ip *ip_header) {
    printf("IP Header\n");
    printf("    Source IP Address: %s\n", inet_ntoa(ip_header->ip_src));
    printf("    Destination IP Address: %s\n", inet_ntoa(ip_header->ip_dst));
}

// TCP Header 출력 함수
void printTCPHeader(const struct tcphdr *tcp_header) {
    printf("TCP Header\n");
    printf("    Source Port: %d\n", ntohs(tcp_header->th_sport));
    printf("    Destination Port: %d\n", ntohs(tcp_header->th_dport));
}

// 패킷 처리 함수
void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Ethernet 헤더에서 바로 IP 헤더를 확인
    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // IP 헤더를 가져옴
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        if (ip_header->ip_p == IPPROTO_TCP) {
            // TCP 헤더를 가져옴
            int ip_header_len = ip_header->ip_hl * 4;
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
            // 출력 함수 호출
            printEthernetHeader(eth_header);
            printIPHeader(ip_header);
            printTCPHeader(tcp_header);
            printf("\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = "ens33"; // 네트워크 인터페이스 선택

    // 네트워크 디바이스 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        return 1;
    }

    // 패킷 처리 루프 실행
    pcap_loop(handle, 0, processPacket, NULL);

    pcap_close(handle);
    return 0;
}
