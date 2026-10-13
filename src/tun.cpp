#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <cstdio>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <array>
#include <span>
#include "constants.hpp"
#include "structures.hpp"
#include "globals.hpp"
#include "utils.hpp"
#include "handlers.hpp"

int main() {
    // ---------- RAW-сокет ----------
    g_raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_raw_fd < 0) {
        perror("socket");
        return 1;
    }

    int ifindex = if_nametoindex(UPF_CN_IFACE);
    if (ifindex == 0) {
        perror("if_nametoindex");
        close(g_raw_fd);
        return 1;
    }

    sockaddr_ll sll{};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ifindex;

    if (bind(g_raw_fd, reinterpret_cast<sockaddr*>(&sll), sizeof(sll))) {
        perror("bind");
        close(g_raw_fd);
        return 1;
    }

    printf("Bound to upf_cn_veth (ifindex=%d), fd=%d\n", ifindex, g_raw_fd);

    // ---------- Свой MAC ----------
    if (!getMacAddress(UPF_CN_IFACE, g_our_mac)) {
        perror("getMacAddress");
        close(g_raw_fd);
        return 1;
    }
    printf("Our MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           g_our_mac[0], g_our_mac[1], g_our_mac[2],
           g_our_mac[3], g_our_mac[4], g_our_mac[5]);

    // ---------- UDP-сокет ----------
    g_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_udp_fd < 0) {
        perror("udp socket");
        close(g_raw_fd);
        return 1;
    }

    sockaddr_in udp_addr{};
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_port = htons(GTP_U_PORT);
    udp_addr.sin_addr.s_addr = inet_addr(UPF_AN_IP);

    if (bind(g_udp_fd, reinterpret_cast<sockaddr*>(&udp_addr), sizeof(udp_addr)) < 0) {
        perror("udp bind");
        close(g_udp_fd);
        close(g_raw_fd);
        return 1;
    }
    printf("UDP socket opened on 192.168.9.1:2152\n");

    // ---------- Адрес gNB ----------
    g_gnb_addr.sin_family = AF_INET;
    g_gnb_addr.sin_port = htons(GTP_U_PORT);
    g_gnb_addr.sin_addr.s_addr = inet_addr(GNB_IP);

    // ---------- epoll ----------
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        close(g_udp_fd);
        close(g_raw_fd);
        return 1;
    }

    epoll_event ev{};
    ev.events = EPOLLIN;

    ev.data.fd = g_raw_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, g_raw_fd, &ev) < 0) {
        perror("epoll_ctl raw");
        return 1;
    }

    ev.data.fd = g_udp_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, g_udp_fd, &ev) < 0) {
        perror("epoll_ctl udp");
        return 1;
    }

    printf("epoll set up, waiting for events... (Ctrl+C to stop)\n");

    // ---------- Основной цикл ----------
    const int MAX_EVENTS = 10;
    epoll_event events[MAX_EVENTS];

    while (true) {
        int n = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == g_raw_fd) {
                handleRaw();
            } else if (events[i].data.fd == g_udp_fd) {
                handleUdp();
            }
        }
    }

    close(epfd);
    close(g_udp_fd);
    close(g_raw_fd);
    return 0;
}
