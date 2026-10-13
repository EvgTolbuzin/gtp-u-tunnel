#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "constants.hpp"

// ARP-заголовок (RFC 826). 28 байт.
struct ArpHeader {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_len;
    uint8_t  proto_len;
    uint16_t opcode;
    uint8_t  sender_mac[MAC_LEN];
    uint32_t sender_ip;
    uint8_t  target_mac[MAC_LEN];
    uint32_t target_ip;
} __attribute__((packed));

// IPv4-заголовок (RFC 791). Минимум 20 байт.
struct IpHeader {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed));

// Описание одного UE.
struct Ue {
    uint32_t ip;
    uint32_t teid_dl;
    uint32_t teid_ul;
};

// Параметры туннелей (из задания).
inline const Ue UES[] = {
    { inet_addr("192.168.7.1"), 2, 3 },
    { inet_addr("192.168.7.2"), 4, 5 },
    { inet_addr("192.168.7.3"), 6, 7 },
    { inet_addr("192.168.7.4"), 8, 9 },
};
