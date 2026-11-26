//parse.c
#include <stdio.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <netinet/icmp6.h>
#include <string.h>
#include <netinet/in.h>

#include "structures.h"

void parse_ether(struct packet* pkt, const uint8_t* p, size_t caplen)
{
    if(caplen < ETH_LEN) return;

    memcpy(pkt->eth.dest, p, MAC_LEN);
    memcpy(pkt->eth.source, p + 6, MAC_LEN);

    const struct ethhdr* eth = (const struct ethhdr*)p;

    pkt->eth.ethertype = ntohs(eth->h_proto);

    pkt->eth.present = true;
}

void parse_ipv4(struct packet* pkt, const uint8_t* p, size_t caplen)
{
    if(caplen < sizeof(struct iphdr)) return;

    const struct iphdr* ip = (const struct iphdr*)p;

    if(ip->ihl < 5 
    || ip->version != 4 
    || ntohs(ip->tot_len) < ip->ihl * 4
    || (size_t)ip->ihl * 4 > caplen) return;

    pkt->ip4.ihl      = ip->ihl;
    pkt->ip4.ttl      = ip->ttl;
    pkt->ip4.protocol = ip->protocol;
    pkt->ip4.total_len = ntohs(ip->tot_len);
    memcpy(&pkt->ip4.src, &ip->saddr, sizeof(struct in_addr));// IP отправителя
    memcpy(&pkt->ip4.dst, &ip->daddr, sizeof(struct in_addr));// IP получателя

    pkt->ip4.present = true;
}
void parse_ipv6(struct packet* pkt, const uint8_t* p, size_t caplen)// СЛОМАНЫЙ!!! либо sniff ломаный
{
    if(caplen < sizeof(struct ipv6hdr)) return;

    const struct ipv6hdr* ip6 = (const struct ipv6hdr*)p;

    if(ip6->version != 6) return;

    memcpy(&pkt->ip6.src, &ip6->saddr, sizeof(struct in6_addr));
    memcpy(&pkt->ip6.dst, &ip6->daddr, sizeof(struct in6_addr));
    pkt->ip6.hop_limit = ip6->hop_limit;
    pkt->ip6.payload_len = ntohs(ip6->payload_len);
    pkt->ip6.nexthdr = ip6->nexthdr;

    pkt->ip6.present = true;
}
void parse_tcp(struct packet* pkt, const uint8_t* p, size_t caplen)
{
    if(caplen < sizeof(struct tcphdr)) return;

    const struct tcphdr* tcp = (const struct tcphdr*)p;

    if (tcp->doff < 5) return;
    if ((size_t)tcp->doff * 4 > caplen) return;

    pkt->tcp.sport = ntohs(tcp->source);
    pkt->tcp.dport = ntohs(tcp->dest);
    pkt->tcp.window = ntohs(tcp->window);
    pkt->tcp.seq = ntohl(tcp->seq);
    pkt->tcp.ack = ntohl(tcp->ack_seq);
    pkt->tcp.doff = tcp->doff;

    uint8_t flags_byte = p[13];
    pkt->tcp.flags = flags_byte;

    pkt->tcp.present = true;
}
void parse_udp(struct packet* pkt, const uint8_t* p, size_t caplen)
{
    if(caplen < sizeof(struct udphdr)) return;

    const struct udphdr* udp = (const struct udphdr*)p;

    uint16_t udp_len = ntohs(udp->len);

    if (udp_len < 8) return;        // заголовок не влезает в заявленную длину
    if (udp_len > caplen) return;   // обрезано

    pkt->udp.sport = ntohs(udp->source);
    pkt->udp.dport = ntohs(udp->dest);
    pkt->udp.length = udp_len;

    pkt->udp.present = true;
}
void parse_icmpv4(struct packet* pkt, const uint8_t* p, size_t caplen)
{
    if(caplen < sizeof(struct icmphdr)) return;

    const struct icmphdr* icmpv4 = (const struct icmphdr*)p;

    pkt->icmpv4.type = icmpv4->type;
    pkt->icmpv4.code = icmpv4->code;
    
    pkt->icmpv4.present = true;
}
void parse_icmpv6(struct packet* pkt, const uint8_t* p, size_t caplen)
{
    if(caplen < sizeof(struct icmp6_hdr)) return;

    const struct icmp6_hdr* icmpv6 = (const struct icmp6_hdr*)p;

    pkt->icmpv6.type = icmpv6->icmp6_type;
    pkt->icmpv6.code = icmpv6->icmp6_code;

    pkt->icmpv6.present = true;

}
void parse_arp(struct packet* pkt, const uint8_t* p, size_t caplen)
{
    if(caplen < 28) return;

    const struct arphdr* arp = (const struct arphdr*)p;

    if (ntohs(arp->ar_hrd) != 1 // Ethernet
    || ntohs(arp->ar_pro) != 0x0800 || arp->ar_hln != 6 //IPv4
    || arp->ar_pln != 4) return;
    
    pkt->arp.oper = ntohs(arp->ar_op);                    // операция из структуры
    memcpy(pkt->arp.mac, p + 8,  MAC_LEN);                // MAC отправителя
    memcpy(&pkt->arp.spa, p + 14, sizeof(struct in_addr));// IP отправителя
    memcpy(&pkt->arp.tpa, p + 24, sizeof(struct in_addr));// IP получателя

    pkt->arp.present = true;
}
