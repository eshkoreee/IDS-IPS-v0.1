
#pragma once

#include <stddef.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <netinet/icmp6.h>
#include "structures.h"

void parse_ether(struct packet* pkt, const uint8_t* p, size_t caplen);
void parse_ipv4(struct packet* pkt, const uint8_t* p, size_t caplen);
void parse_ipv6(struct packet* pkt, const uint8_t* p, size_t caplen);
void parse_tcp(struct packet* pkt, const uint8_t* p, size_t caplen);
void parse_udp(struct packet* pkt, const uint8_t* p, size_t caplen);
void parse_icmpv4(struct packet* pkt, const uint8_t* p, size_t caplen);
void parse_icmpv6(struct packet* pkt, const uint8_t* p, size_t caplen);
void parse_arp(struct packet* pkt, const uint8_t* p, size_t caplen);

