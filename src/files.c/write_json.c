
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdint.h>
#include "structures.h"

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

static void write_time(FILE* f)
{
    struct timespec time_ns;
    if (clock_gettime(CLOCK_REALTIME, &time_ns) == -1) {
        fprintf(f, "\"time\":\"%s\"", "null");
        return;
    }
    uint64_t tm_ns = (uint64_t)time_ns.tv_sec * 1000000000ULL + (uint64_t)time_ns.tv_nsec;
    fprintf(f, "\"time\":%llu", tm_ns);
    fputc(',', f);
}

void write_severity(FILE* f)
{

}

static void write_arp(FILE* f, struct packet* pkt)
{
    if (!pkt->arp.present) return;
    char spa_str[INET_ADDRSTRLEN];
    char tpa_str[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, &pkt->arp.spa, spa_str, sizeof(spa_str)) == NULL)
    snprintf(spa_str, sizeof(spa_str), "null");

    if (inet_ntop(AF_INET, &pkt->arp.tpa, tpa_str, sizeof(tpa_str)) == NULL)
    snprintf(tpa_str, sizeof(tpa_str), "null");

    const char* oper_str = (pkt->arp.oper == 1) ? "REQUEST" : (pkt->arp.oper == 2) ? "REPLY" : "UNKNOWN";

    fprintf(f, "\"arp\":{\"oper\":%u,\"oper_str\":\"%s\",\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"spa\":\"%s\",\"tpa\":\"%s\"}", (unsigned)pkt->arp.oper, oper_str, \
    pkt->arp.mac[0], pkt->arp.mac[1], pkt->arp.mac[2], pkt->arp.mac[3], pkt->arp.mac[4], pkt->arp.mac[5], spa_str, tpa_str);
    fputc(',', f);
}

static inline void write_ether(FILE* f, struct packet* pkt)
{
    if (!pkt->eth.present) return;
    fprintf(f, "\"eth\":{\"src\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \
        \"dst\":\"%02x:%02x:%02x:%02x:%02x:%02x\", \"ethertype\":\"0x%04x\"}", pkt->eth.source[0], pkt->eth.source[1],  pkt->eth.source[2], pkt->eth.source[3], pkt->eth.source[4], pkt->eth.source[5], \
        pkt->eth.dest[0], pkt->eth.dest[1],  pkt->eth.dest[2], pkt->eth.dest[3], pkt->eth.dest[4], pkt->eth.dest[5], pkt->eth.ethertype);
        fputc(',', f);

}

static void write_ipv4(FILE* f, struct packet* pkt)
{
    if (!pkt->ip4.present) return;
    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &pkt->ip4.src, src_str, sizeof(src_str)) == NULL)
    snprintf(src_str, sizeof(src_str), "null");

    if (inet_ntop(AF_INET, &pkt->ip4.dst, dst_str, sizeof(dst_str)) == NULL)
    snprintf(dst_str, sizeof(dst_str), "null");
    const char* proto_name =
    (pkt->ip4.protocol == 1)  ? "ICMP" :
    (pkt->ip4.protocol == 6)  ? "TCP"  :
    (pkt->ip4.protocol == 17) ? "UDP"  : "UNKNOWN";

    fprintf(f,"\"ip4\":{\"src\":\"%s\",\"dst\":\"%s\", \
        \"protocol\":%u,\"protocol_name\":\"%s\", \
        \"ttl\":%u,\"total_len\":%u,\"ihl\":%u}", \
        src_str, dst_str,
        (unsigned)pkt->ip4.protocol, proto_name,
        (unsigned)pkt->ip4.ttl,
        (unsigned)pkt->ip4.total_len,
        (unsigned)pkt->ip4.ihl);
        fputc(',', f);
}

static void write_ipv6(FILE* f, struct packet* pkt)
{
    if (!pkt->ip6.present) return;
    char src_str[INET6_ADDRSTRLEN];
    char dst_str[INET6_ADDRSTRLEN];

    if (inet_ntop(AF_INET6, &pkt->ip6.src, src_str, sizeof(src_str)) == NULL)
    snprintf(src_str, sizeof(src_str), "null");

    if (inet_ntop(AF_INET6, &pkt->ip6.dst, dst_str, sizeof(dst_str)) == NULL)
    snprintf(dst_str, sizeof(dst_str), "null");

    const char* proto_name =
    (pkt->ip6.nexthdr == 58) ? "ICMPv6" :
    (pkt->ip6.nexthdr == 6)  ? "TCP"    :
    (pkt->ip6.nexthdr == 17) ? "UDP"    :
    (pkt->ip6.nexthdr == 0)  ? "HOPOPT" :
    (pkt->ip6.nexthdr == 43) ? "ROUTING":
    (pkt->ip6.nexthdr == 44) ? "FRAGMENT":
    (pkt->ip6.nexthdr == 60) ? "DSTOPTS": "UNKNOWN";

    fprintf(f, "\"ip6\":{\"src\":\"%s\",\"dst\":\"%s\",\"hop_limit\":%u,\"payload_len\":%u,\"nexthdr\":%u,\"nexthdr_name\":\"%s\"}",
        src_str, dst_str, (unsigned)pkt->ip6.hop_limit, (unsigned)pkt->ip6.payload_len, (unsigned)pkt->ip6.nexthdr, proto_name);
        fputc(',', f);
}

static void write_tcp(FILE* f, struct packet* pkt)
{
    if (!pkt->tcp.present) return;
    // флаги в строку
    char flags_str[64] = {0};
    if (pkt->tcp.flags & TCP_FIN) strcat(flags_str, "FIN,");
    if (pkt->tcp.flags & TCP_SYN) strcat(flags_str, "SYN,");
    if (pkt->tcp.flags & TCP_RST) strcat(flags_str, "RST,");
    if (pkt->tcp.flags & TCP_PSH) strcat(flags_str, "PSH,");
    if (pkt->tcp.flags & TCP_ACK) strcat(flags_str, "ACK,");
    if (pkt->tcp.flags & TCP_URG) strcat(flags_str, "URG,");
    if (pkt->tcp.flags & TCP_ECE) strcat(flags_str, "ECE,");
    if (pkt->tcp.flags & TCP_CWR) strcat(flags_str, "CWR,");

    size_t len = strlen(flags_str);           // узнать длину
    if (len > 0 && flags_str[len - 1] == ',') flags_str[len - 1] = '\0'; // проверить: не пусто и последний символ — запятая

    if (len == 0) snprintf(flags_str, sizeof(flags_str), "NONE"); // если ни один флаг не был установлен

    fprintf(f, "\"tcp\":{\"sport\":%u,\"dport\":%u,\"seq\":%u,\"ack\":%u,\"window\":%u,\"doff\":%u,\"flags_raw\":%u,\"flags\":\"%s\"}",
    (unsigned)pkt->tcp.sport, (unsigned)pkt->tcp.dport, (unsigned)pkt->tcp.seq, (unsigned)pkt->tcp.ack, (unsigned)pkt->tcp.window,
    (unsigned)pkt->tcp.doff, (unsigned)pkt->tcp.flags, flags_str);

    fputc(',', f);
}

static inline void write_udp(FILE* f, struct packet* pkt)
{
    if (!pkt->udp.present) return;

    fprintf(f, "\"udp\":{\"sport\":%u,\"dport\":%u,\"length\":%u}",
    (unsigned)pkt->udp.sport, (unsigned)pkt->udp.dport, (unsigned)pkt->udp.length);

    fputc(',', f);
}

static void write_icmpv4(FILE* f, struct packet* pkt)
{
    if (!pkt->icmpv4.present) return;

    const char* type_name =
    (pkt->icmpv4.type == 0)  ? "ECHO_REPLY" :
    (pkt->icmpv4.type == 3)  ? "DEST_UNREACH" :
    (pkt->icmpv4.type == 8)  ? "ECHO_REQUEST" :
    (pkt->icmpv4.type == 11) ? "TIME_EXCEEDED" : "UNKNOWN";

    fprintf(f, "\"icmpv4\":{\"type\":%u,\"type_name\":\"%s\",\"code\":%u}", (unsigned)pkt->icmpv4.type, type_name, (unsigned)pkt->icmpv4.code);

    fputc(',', f);
}

static void write_icmpv6(FILE* f, struct packet* pkt)
{
    if (!pkt->icmpv6.present) return;

    const char* type_name =
    (pkt->icmpv6.type == 128) ? "ECHO_REQUEST" :
    (pkt->icmpv6.type == 129) ? "ECHO_REPLY"   :
    (pkt->icmpv6.type == 1)   ? "DEST_UNREACH" :
    (pkt->icmpv6.type == 2)   ? "PACKET_TOO_BIG" :
    (pkt->icmpv6.type == 3)   ? "TIME_EXCEEDED" :
    (pkt->icmpv6.type == 135) ? "NEIGHBOR_SOL" :
    (pkt->icmpv6.type == 136) ? "NEIGHBOR_ADV" : "UNKNOWN";

    fprintf(f, "\"icmpv6\":{\"type\":%u,\"type_name\":\"%s\",\"code\":%u}", (unsigned)pkt->icmpv6.type, type_name, (unsigned)pkt->icmpv6.code);

    fputc(',', f);
}

/*
этот метод отвечает за валидную запись пакета в .ndjson файл путем вызова методов
с приставкой write_*. ipv6 временно не работает из за временно невыявленных логических
ошибок. в логе не обращать на это внимания
*/

int write_json(FILE* f, struct packet* pkt)
{

    fputc('{', f);
    write_time(f);
    write_severity(f);
    write_ether(f, pkt);
    write_arp(f, pkt);
    write_ipv4(f, pkt);
    write_ipv6(f, pkt);
    write_tcp(f, pkt);
    write_udp(f, pkt);
    write_icmpv4(f, pkt);
    write_icmpv6(f, pkt);
    
    
    off_t pos = ftello(f);
    fseeko(f, pos - 1, SEEK_SET);
    fputs("}\n", f);
    return 0;
}
