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

struct ArpHeader {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_len;
    uint8_t  proto_len;
    uint16_t opcode;
    uint8_t  sender_mac[6];
    uint32_t sender_ip;
    uint8_t  target_mac[6];
    uint32_t target_ip;
} __attribute__((packed));

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

struct Ue {
    uint32_t ip;
    uint32_t teid_dl;
    uint32_t teid_ul;
};

static const Ue UES[] = {
    { inet_addr("192.168.7.1"), 2, 3 },
    { inet_addr("192.168.7.2"), 4, 5 },
    { inet_addr("192.168.7.3"), 6, 7 },
    { inet_addr("192.168.7.4"), 8, 9 },
};

static const Ue* findUeByIp(uint32_t ip) {
    for (const auto& ue : UES) {
        if (ue.ip == ip) return &ue;
    }
    return nullptr;
}

static const Ue* findUeByTeidUl(uint32_t teid_ul) {
    for (const auto& ue : UES) {
        if (ue.teid_ul == teid_ul) return &ue;
    }
    return nullptr;
}

static bool getMacAddress(const char* ifname, uint8_t mac[6]) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return false;
    }
    std::memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return true;
}

static uint8_t g_our_mac[6];
static uint8_t g_dn_mac[6];
static bool    g_dn_mac_known = false;
static sockaddr_in g_gnb_addr{};
static int     g_raw_fd;
static int     g_udp_fd;    

static void printMac(const char* prefix, const uint8_t mac[6]) {
    printf("%s%02x:%02x:%02x:%02x:%02x:%02x\n",
           prefix,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void handleRaw() {
    uint8_t buf[2048];
    ssize_t n = recv(g_raw_fd, buf, sizeof(buf), 0);
    if (n <= 0) {
        perror("recv raw");
        return;
    }
    if (n < 14) return;

    const uint8_t* dst = buf;
    const uint8_t* src = buf + 6;
    const uint16_t ether_type = (buf[12] << 8) | buf[13];

    printf("frame %zd bytes | dst=%02x:%02x:%02x:%02x:%02x:%02x"
           " | src=%02x:%02x:%02x:%02x:%02x:%02x"
           " | type=0x%04x\n",
           n,
           dst[0], dst[1], dst[2], dst[3], dst[4], dst[5],
           src[0], src[1], src[2], src[3], src[4], src[5],
           ether_type);

    // Запоминаем MAC DN
    if (ether_type == 0x0806 && n >= 14 + 28) {
        ArpHeader* arp = (ArpHeader*)(buf + 14);
        if (ntohs(arp->opcode) == 1) {
            bool changed = !g_dn_mac_known ||
                        std::memcmp(g_dn_mac, arp->sender_mac, 6) != 0;
            if (changed) {
                std::memcpy(g_dn_mac, arp->sender_mac, 6);
                g_dn_mac_known = true;
                printf("  Learned DN MAC: ");
                printMac("", g_dn_mac);
            }
        }
    }

    // ---------- ARP ----------
    if (ether_type == 0x0806) {
        if (n >= 14 + 28) {
            ArpHeader* arp = (ArpHeader*)(buf + 14);

            if (ntohs(arp->opcode) == 1 &&
                findUeByIp(arp->target_ip) != nullptr)
            {
                uint8_t reply[14 + 28];
                std::memcpy(reply + 0, arp->sender_mac, 6);
                std::memcpy(reply + 6, g_our_mac, 6);
                reply[12] = 0x08;
                reply[13] = 0x06;

                ArpHeader* r = (ArpHeader*)(reply + 14);
                r->hw_type    = htons(0x0001);
                r->proto_type = htons(0x0800);
                r->hw_len     = 6;
                r->proto_len  = 4;
                r->opcode     = htons(2);

                std::memcpy(r->sender_mac, g_our_mac, 6);
                r->sender_ip = arp->target_ip;
                std::memcpy(r->target_mac, arp->sender_mac, 6);
                r->target_ip = arp->sender_ip;

                if (send(g_raw_fd, reply, sizeof(reply), 0) < 0) {
                    perror("send ARP");
                } else {
                    printf("Sent ARP reply for %u.%u.%u.%u\n",
                           (ntohl(arp->target_ip) >> 24) & 0xFF,
                           (ntohl(arp->target_ip) >> 16) & 0xFF,
                           (ntohl(arp->target_ip) >> 8)  & 0xFF,
                           ntohl(arp->target_ip) & 0xFF);
                }
            }
        }
    }

    // ---------- IPv4 ----------
    if (ether_type == 0x0800) {
        if (n >= 14 + 20) {
            IpHeader* ip = (IpHeader*)(buf + 14);
            uint8_t version = ip->version_ihl >> 4;
            uint8_t ihl     = ip->version_ihl & 0x0F;

            if (version == 4 && ihl >= 5) {
                size_t ip_hdr_len = ihl * 4;
                uint16_t total_len = ntohs(ip->total_length);

                if (static_cast<size_t>(n) >= 14 + ip_hdr_len &&
                    total_len >= ip_hdr_len &&
                    static_cast<size_t>(n) >= static_cast<size_t>(14) + total_len)
                {
                    uint32_t dst_ip = ip->dst_ip;
                    uint8_t  proto  = ip->protocol;
                    const Ue* ue = findUeByIp(dst_ip);

                    if (ue != nullptr) {
                        printf("  IPv4: proto=%u, src=%u.%u.%u.%u, "
                               "dst=%u.%u.%u.%u, total_len=%u, "
                               "ip_hdr_len=%zu, ue_teid_dl=%u\n",
                               proto,
                               (ntohl(ip->src_ip) >> 24) & 0xFF,
                               (ntohl(ip->src_ip) >> 16) & 0xFF,
                               (ntohl(ip->src_ip) >> 8)  & 0xFF,
                               ntohl(ip->src_ip) & 0xFF,
                               (ntohl(dst_ip) >> 24) & 0xFF,
                               (ntohl(dst_ip) >> 16) & 0xFF,
                               (ntohl(dst_ip) >> 8)  & 0xFF,
                               ntohl(dst_ip) & 0xFF,
                               total_len, ip_hdr_len, ue->teid_dl);

                        // GTP-U
                        uint8_t gtp_buf[2048];
                        gtp_buf[0] = 0x30;
                        gtp_buf[1] = 0xFF;
                        uint16_t gtp_length = htons(total_len);
                        std::memcpy(gtp_buf + 2, &gtp_length, 2);
                        uint32_t teid_be = htonl(ue->teid_dl);
                        std::memcpy(gtp_buf + 4, &teid_be, 4);
                        std::memcpy(gtp_buf + 8, buf + 14, total_len);

                        ssize_t s = sendto(g_udp_fd, gtp_buf, 8 + total_len, 0,
                                           (sockaddr*)&g_gnb_addr,
                                           sizeof(g_gnb_addr));
                        if (s < 0) {
                            perror("sendto GTP-U");
                        } else {
                            printf("  Sent GTP-U: %zd bytes to gNB, "
                                   "teid_dl=%u\n", s, ue->teid_dl);
                        }
                    }
                }
            }
        }
    }
}

static void handleUdp() {
    uint8_t udp_buf[2048];
    sockaddr_in from{};
    socklen_t from_len = sizeof(from);

    ssize_t m = recvfrom(g_udp_fd, udp_buf, sizeof(udp_buf), 0,
                         (sockaddr*)&from, &from_len);
    if (m <= 0) return;

    printf("Received UDP: %zd bytes from %s:%u\n",
           m, inet_ntoa(from.sin_addr), ntohs(from.sin_port));

    if (m < 8) {
        printf("  GTP-U too short, skip\n");
        return;
    }

    uint8_t  gtp_version  = (udp_buf[0] >> 5) & 0x07;
    uint8_t  gtp_msg_type = udp_buf[1];
    uint16_t gtp_length   = (udp_buf[2] << 8) | udp_buf[3];
    uint32_t gtp_teid     = (uint32_t(udp_buf[4]) << 24) |
                            (uint32_t(udp_buf[5]) << 16) |
                            (uint32_t(udp_buf[6]) << 8)  |
                             uint32_t(udp_buf[7]);

    printf("  GTP-U: version=%u, type=0x%02x, length=%u, teid=%u\n",
           gtp_version, gtp_msg_type, gtp_length, gtp_teid);

    if (gtp_version != 1 || gtp_msg_type != 0xFF) {
        printf("  Not a G-PDU, skip\n");
        return;
    }
    if (m < 8 + gtp_length) {
        printf("  GTP-U truncated, skip\n");
        return;
    }
    if (gtp_length < 20) {
        printf("  GTP-U payload too small, skip\n");
        return;
    }

    IpHeader* inner_ip = (IpHeader*)(udp_buf + 8);
    uint32_t inner_src = inner_ip->src_ip;

    printf("  Inner IP: src=%u.%u.%u.%u, dst=%u.%u.%u.%u, proto=%u\n",
           (ntohl(inner_src) >> 24) & 0xFF,
           (ntohl(inner_src) >> 16) & 0xFF,
           (ntohl(inner_src) >> 8)  & 0xFF,
           ntohl(inner_src) & 0xFF,
           (ntohl(inner_ip->dst_ip) >> 24) & 0xFF,
           (ntohl(inner_ip->dst_ip) >> 16) & 0xFF,
           (ntohl(inner_ip->dst_ip) >> 8)  & 0xFF,
           ntohl(inner_ip->dst_ip) & 0xFF,
           inner_ip->protocol);

    const Ue* ue = findUeByTeidUl(gtp_teid);
    if (ue == nullptr) {
        printf("  Can't find UE for teid_ul=%u, skip\n", gtp_teid);
        return;
    }
    if (inner_src != ue->ip) {
        printf("  SECURITY: inner src != ue ip, drop\n");
        return;
    }
    if (!g_dn_mac_known) {
        printf("  DN MAC not known yet, skip\n");
        return;
    }

    uint8_t frame[2048];
    std::memcpy(frame + 0, g_dn_mac, 6);
    std::memcpy(frame + 6, g_our_mac, 6);
    frame[12] = 0x08;
    frame[13] = 0x00;
    std::memcpy(frame + 14, udp_buf + 8, gtp_length);

    ssize_t s = send(g_raw_fd, frame, 14 + gtp_length, 0);
    if (s < 0) {
        perror("send to DN");
    } else {
        printf("  Sent %zd bytes to DN (from UE %u.%u.%u.%u)\n",
               s,
               (ntohl(ue->ip) >> 24) & 0xFF,
               (ntohl(ue->ip) >> 16) & 0xFF,
               (ntohl(ue->ip) >> 8)  & 0xFF,
               ntohl(ue->ip) & 0xFF);
    }
}

int main() {
    // ---------- RAW-сокет ----------
    g_raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_raw_fd < 0) {
        perror("socket");
        return 1;
    }

    int ifindex = if_nametoindex("upf_cn_veth");
    if (ifindex == 0) {
        perror("if_nametoindex");
        close(g_raw_fd);
        return 1;
    }

    sockaddr_ll sll{};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ifindex;

    if (bind(g_raw_fd, (sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(g_raw_fd);
        return 1;
    }

    printf("Bound to upf_cn_veth (ifindex=%d), fd=%d\n", ifindex, g_raw_fd);

    // ---------- Свой MAC ----------
    if (!getMacAddress("upf_cn_veth", g_our_mac)) {
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
    udp_addr.sin_port = htons(2152);
    udp_addr.sin_addr.s_addr = inet_addr("192.168.9.1");

    if (bind(g_udp_fd, (sockaddr*)&udp_addr, sizeof(udp_addr)) < 0) {
        perror("udp bind");
        close(g_udp_fd);
        close(g_raw_fd);
        return 1;
    }
    printf("UDP socket opened on 192.168.9.1:2152\n");

    // ---------- Адрес gNB ----------
    g_gnb_addr.sin_family = AF_INET;
    g_gnb_addr.sin_port = htons(2152);
    g_gnb_addr.sin_addr.s_addr = inet_addr("192.168.9.2");

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
