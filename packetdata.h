#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#ifndef PACKETDATA_H
#define PACKETDATA_H

#endif // PACKETDATA_H

struct Ethernet{
    uint8_t d_mac[6];
    uint8_t s_mac[6];
    uint16_t type;
};

struct Ip{
//    unsigned int version:4;
//   unsigned int ihl:4;
    uint8_t VHL;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t s_ip;
    uint32_t d_ip;
};

struct Tcp{
    uint16_t s_port;
    uint16_t d_port;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t need;
    uint16_t res1:4;
    uint16_t doff:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t res2:2;
};
