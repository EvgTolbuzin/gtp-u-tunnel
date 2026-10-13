#include "globals.hpp"

uint8_t g_our_mac[MAC_LEN] = {};
uint8_t g_dn_mac[MAC_LEN] = {};
bool    g_dn_mac_known = false;
sockaddr_in g_gnb_addr{};
int     g_raw_fd = -1;
int     g_udp_fd = -1;