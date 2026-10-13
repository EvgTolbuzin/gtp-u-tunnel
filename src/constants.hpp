#pragma once

#include <cstddef>
#include <cstdint>

// Ethernet-типы (поле ether_type)
constexpr uint16_t ETH_TYPE_IPV4 = 0x0800;
constexpr uint16_t ETH_TYPE_ARP  = 0x0806;
constexpr uint16_t ETH_TYPE_IPV6 = 0x86DD;

// Длины заголовков (в байтах)
constexpr size_t ETH_HEADER_LEN = 14;
constexpr size_t ARP_HEADER_LEN = 28;
constexpr size_t IP_MIN_HEADER_LEN = 20;
constexpr size_t GTP_U_HEADER_LEN = 8;

// ARP
constexpr uint16_t ARP_HW_TYPE_ETHERNET = 0x0001;
constexpr uint16_t ARP_PROTO_TYPE_IPV4  = 0x0800;
constexpr uint16_t ARP_OP_REQUEST = 1;
constexpr uint16_t ARP_OP_REPLY   = 2;

// IP-протоколы (поле protocol)
constexpr uint8_t IP_PROTO_ICMP = 1;
constexpr uint8_t IP_PROTO_TCP  = 6;
constexpr uint8_t IP_PROTO_UDP  = 17;

// GTP-U
constexpr uint16_t GTP_U_PORT = 2152;
constexpr uint8_t  GTP_U_FLAGS_G_PDU   = 0x30;   // version=1, PT=1
constexpr uint8_t  GTP_U_MSG_TYPE_G_PDU = 0xFF;

// MAC-адреса
constexpr size_t MAC_LEN = 6;

// Параметры нашей сети (из enable_net.sh)
constexpr const char* UPF_CN_IFACE = "upf_cn_veth";
constexpr const char* UPF_AN_IP    = "192.168.9.1";
constexpr const char* GNB_IP       = "192.168.9.2";

// Размер буфера для чтения
constexpr size_t BUF_SIZE = 2048;