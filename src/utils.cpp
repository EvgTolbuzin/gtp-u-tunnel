#include "utils.hpp"
#include <cstdio>
#include <cstring>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

const Ue* findUeByIp(uint32_t ip) {
    for (const auto& ue : UES) {
        if (ue.ip == ip) return &ue;
    }
    return nullptr;
}

const Ue* findUeByTeidUl(uint32_t teid_ul) {
    for (const auto& ue : UES) {
        if (ue.teid_ul == teid_ul) return &ue;
    }
    return nullptr;
}

bool getMacAddress(const char* ifname, uint8_t mac[MAC_LEN]) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return false;
    }
    std::memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LEN);
    close(fd);
    return true;
}

void printMac(const char* prefix, const uint8_t mac[MAC_LEN]) {
    printf("%s%02x:%02x:%02x:%02x:%02x:%02x\n",
           prefix,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
