#include "handlers.hpp"
#include "globals.hpp"
#include "structures.hpp"
#include "utils.hpp"
#include <array>
#include <span>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

void handleRaw() {
    std::array<uint8_t, BUF_SIZE> buf;
    ssize_t n = recv(g_raw_fd, buf.data(), buf.size(), 0);
    if (n <= 0) {
        perror("recv raw");
        return;
    }
    std::span<uint8_t> frame(buf.data(), static_cast<size_t>(n));
    if (frame.size() < ETH_HEADER_LEN) return;

    const uint8_t* dst = buf.data();
    const uint8_t* src = buf.data() + MAC_LEN;
    const uint16_t ether_type = (buf[12] << 8) | buf[13];

    printf("frame %zd bytes | dst=%02x:%02x:%02x:%02x:%02x:%02x"
           " | src=%02x:%02x:%02x:%02x:%02x:%02x"
           " | type=0x%04x\n",
           n,
           dst[0], dst[1], dst[2], dst[3], dst[4], dst[5],
           src[0], src[1], src[2], src[3], src[4], src[5],
           ether_type);

    // Запоминаем MAC DN
    if (ether_type == ETH_TYPE_ARP && n >= static_cast<ssize_t>(ETH_HEADER_LEN + ARP_HEADER_LEN)) {
        ArpHeader* arp = reinterpret_cast<ArpHeader*>(buf.data() + ETH_HEADER_LEN);
        if (ntohs(arp->opcode) == 1) {
            bool changed = !g_dn_mac_known || std::memcmp(g_dn_mac, arp->sender_mac, MAC_LEN) != 0;
            if (changed) {
                std::memcpy(g_dn_mac, arp->sender_mac, MAC_LEN);
                g_dn_mac_known = true;
                printf("  Learned DN MAC: ");
                printMac("", g_dn_mac);
            }
        }
    }

    // ---------- ARP ----------
    if (ether_type == ETH_TYPE_ARP) {
        if (n >= static_cast<ssize_t>(ETH_HEADER_LEN + ARP_HEADER_LEN)) {
            auto* arp = reinterpret_cast<ArpHeader*>(buf.data() + ETH_HEADER_LEN);

            if (ntohs(arp->opcode) == ARP_OP_REQUEST &&
                findUeByIp(arp->target_ip) != nullptr)
            {
                std::array<uint8_t, ETH_HEADER_LEN + ARP_HEADER_LEN> reply;
                std::memcpy(reply.data(), arp->sender_mac, MAC_LEN);
                std::memcpy(reply.data() + MAC_LEN, g_our_mac, MAC_LEN);
                reply[12] = (ETH_TYPE_ARP >> 8) & 0xFF;
                reply[13] = ETH_TYPE_ARP & 0xFF;

                ArpHeader* r = reinterpret_cast<ArpHeader*>(reply.data() + ETH_HEADER_LEN);
                r->hw_type    = htons(ARP_HW_TYPE_ETHERNET);
                r->proto_type = htons(ARP_PROTO_TYPE_IPV4);
                r->hw_len     = MAC_LEN;
                r->proto_len  = 4;
                r->opcode     = htons(ARP_OP_REPLY);

                std::memcpy(r->sender_mac, g_our_mac, MAC_LEN);
                r->sender_ip = arp->target_ip;
                std::memcpy(r->target_mac, arp->sender_mac, MAC_LEN);
                r->target_ip = arp->sender_ip;

                if (send(g_raw_fd, reply.data(), reply.size(), 0) < 0) {
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
    if (ether_type == ETH_TYPE_IPV4) {
        if (n >= static_cast<ssize_t>(ETH_HEADER_LEN + IP_MIN_HEADER_LEN)) {
            IpHeader* ip = reinterpret_cast<IpHeader*>(buf.data() + ETH_HEADER_LEN);
            uint8_t version = ip->version_ihl >> 4;
            uint8_t ihl     = ip->version_ihl & 0x0F;

            if (version == 4 && ihl >= 5) {
                size_t ip_hdr_len = ihl * 4;
                uint16_t total_len = ntohs(ip->total_length);

                if (static_cast<size_t>(n) >= ETH_HEADER_LEN + ip_hdr_len &&
                    total_len >= ip_hdr_len &&
                    static_cast<size_t>(n) >= ETH_HEADER_LEN + total_len)
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
                        std::array<uint8_t, BUF_SIZE> gtp_buf;
                        gtp_buf[0] = GTP_U_FLAGS_G_PDU;
                        gtp_buf[1] = GTP_U_MSG_TYPE_G_PDU   ;
                        uint16_t gtp_length = htons(total_len);
                        std::memcpy(gtp_buf.data() + 2, &gtp_length, 2);
                        uint32_t teid_be = htonl(ue->teid_dl);
                        std::memcpy(gtp_buf.data() + 4, &teid_be, 4);
                        std::memcpy(gtp_buf.data() + GTP_U_HEADER_LEN, buf.data() + ETH_HEADER_LEN, total_len);

                        ssize_t s = sendto(g_udp_fd, gtp_buf.data(), GTP_U_HEADER_LEN + total_len, 0,
                                           reinterpret_cast<sockaddr*>(&g_gnb_addr),
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

void handleUdp() {
    std::array<uint8_t, BUF_SIZE> udp_buf;
    sockaddr_in from{};
    socklen_t from_len = sizeof(from);

    ssize_t m = recvfrom(g_udp_fd, udp_buf.data(), udp_buf.size(), 0,
                         reinterpret_cast<sockaddr*>(&from), &from_len);
    if (m <= 0) return;

    printf("Received UDP: %zd bytes from %s:%u\n",
           m, inet_ntoa(from.sin_addr), ntohs(from.sin_port));

    if (m < static_cast<ssize_t>(GTP_U_HEADER_LEN)) {
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

    if (gtp_version != 1 || gtp_msg_type != GTP_U_MSG_TYPE_G_PDU) {
        printf("  Not a G-PDU, skip\n");
        return;
    }
    if (m < static_cast<ssize_t>(GTP_U_HEADER_LEN) + gtp_length) {
        printf("  GTP-U truncated, skip\n");
        return;
    }
    if (gtp_length < IP_MIN_HEADER_LEN) {
        printf("  GTP-U payload too small, skip\n");
        return;
    }

    IpHeader* inner_ip = reinterpret_cast<IpHeader*>(udp_buf.data() + GTP_U_HEADER_LEN);
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

    std::array<uint8_t, BUF_SIZE> frame;
    std::memcpy(frame.data(), g_dn_mac, MAC_LEN);
    std::memcpy(frame.data() + MAC_LEN, g_our_mac, MAC_LEN);
    frame[12] = (ETH_TYPE_IPV4 >> 8) & 0xFF;
    frame[13] = ETH_TYPE_IPV4 & 0xFF;
    std::memcpy(frame.data() + ETH_HEADER_LEN, udp_buf.data() + GTP_U_HEADER_LEN, gtp_length);

    ssize_t s = send(g_raw_fd, frame.data(), ETH_HEADER_LEN + gtp_length, 0);
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
