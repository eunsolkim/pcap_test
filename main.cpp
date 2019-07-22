#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "packetdata.h"

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

void print_mac(u_char* packet) {
    printf("%02X:%02X:%02X:%02X:%02X:%02x\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
}

void print_ip(uint32_t ip) {
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    printf("%s\n", inet_ntoa(ip_addr));
}

void print_port(uint16_t port){
    uint16_t p = ((port & 0x00ff) << 8) | ((port & 0xff00) >> 8);
    printf("%d\n", p);
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
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while(true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        struct Ethernet* e = (struct Ethernet*)(packet);
        int ip_len = 0;

        if(e->type == ntohs(0x0800) ){
            struct Ip* i = (struct Ip*)(packet + 14);
            ip_len = (i->VHL & 0x0F) * 4;

            if(i->protocol == 0x06){
                struct Tcp* t = (struct Tcp*)(packet + 14 + ip_len);
                int tcp_len = ((t->need & 0xF0) >> 4) * 4;

                printf("--------------------------\n\n");
                printf("s-mac : ");
                print_mac(e->s_mac);
                printf("d-mac : ");
                print_mac(e->d_mac);
                printf("s-ip : ");
                print_ip(i->s_ip);
                printf("d-ip : ");
                print_ip(i->d_ip);
                printf("s-port : ");
                print_port(t->s_port);
                printf("d-port : ");
                print_port(t->d_port);
                printf("\n");

                u_char * payload = (u_char *)(packet + 14 + ip_len + tcp_len);
                int payload_len = ntohs(i->tot_len) - (ip_len + tcp_len);

                for(int i=0; i<10; i++){
                    if(i>=payload_len){
                        printf("No Data");
                        break;
                    }
                    printf("%02X ", payload[i]);
                }
                printf("\n");
                printf("%u bytes captured\n", header->caplen);
                //printf("%u bytes payload captured\n", payload_len);
                //printf("%d = ip\n %d = tcp \n", ip_len, tcp_len);
                printf("--------------------------\n\n");
            }
        }
    }

    pcap_close(handle);
    return 0;
}
