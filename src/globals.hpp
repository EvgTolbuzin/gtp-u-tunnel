#pragma once

#include <cstdint>
#include <netinet/in.h>
#include "constants.hpp"

extern uint8_t g_our_mac[MAC_LEN];
extern uint8_t g_dn_mac[MAC_LEN];
extern bool    g_dn_mac_known;
extern sockaddr_in g_gnb_addr;
extern int     g_raw_fd;
extern int     g_udp_fd;
