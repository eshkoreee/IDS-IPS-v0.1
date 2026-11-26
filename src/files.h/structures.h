
#pragma once

#include <stdint.h>
#include <netinet/in.h>
#include <stdbool.h>

#define ETH_LEN     14
#define MAC_LEN     6
#define IPv4_LEN    4
#define IPV6HDR_len 40
#define ETH_P_IPV4  0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_P_ARP   0x0806

struct eth_in
{
    bool present;
    unsigned char dest[6];   // MAC получатель
    unsigned char source[6]; // MAC отправитель
    uint16_t ethertype; // что дальше
};
struct ipv4_in
{
    bool     present;   // использовалась ли структура
    uint8_t  ihl;       // в 32-битных словах
    uint8_t  ttl;       // сколько живет пакет
    uint8_t  protocol;  // какой L4 протокол
    uint16_t total_len; // длина после вычисления ihl
    struct in_addr src; // айпи отправитель
    struct in_addr dst; // айпи получатель

    // Поля для фрагментации (можно заполнять позже)
    uint16_t id;
    uint16_t frag_off;      // offset + flags в сыром виде
    bool     dont_fragment;
    bool     more_fragments;
};
struct ipv6_in
{
    bool present;
    struct in6_addr src; // айпи отправитель
    struct in6_addr dst; // айпи получатель
    uint8_t hop_limit;  // время жизни
    uint8_t nexthdr;        // исходный, может указывать на ext header
    uint16_t payload_len;    // host order

    uint8_t       final_nexthdr; // заголовки расширения
    uint8_t       traffic_class;
    uint32_t      flow_label;
};
struct tcp_in
{
    bool     present;
    uint16_t sport;       // порт отправитель
    uint16_t dport;       // порт получатель
    uint32_t seq;         // какой байт потока передается. позволяет узнавать потери, дубликаты, несостыковки
    uint32_t ack;         // какой байт ожидает отправитель. работает при рабочем флаге ACK
    uint16_t window;      // сколько данных готов съесть получатель за раз
    uint8_t  doff;        // data offset в 32-битных словах
    uint8_t  flags;       // битовая маска: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20
};
struct udp_in
{
    bool     present;
    uint16_t sport;       // порт отправитель
    uint16_t dport;       // порт получатель
    uint16_t length;      // host order, включает 8 байт заголовка
};
struct icmpv4_in
{
    bool     present;
    uint8_t  type;
    uint8_t  code;

    // Только для Echo (type 0 или 8) — иначе нули 
    bool     is_echo;
    uint16_t id;
    uint16_t seq;

    // Для Type 3 Code 4 (Fragmentation Needed) — Next-Hop MTU значит пакет слишком большой но фрагментировать нельзя
    bool     has_mtu;
    uint16_t next_hop_mtu; // максимальный размер пакета который может пройти за раз
};
struct icmpv6_in
{
    bool     present;
    uint8_t  type;
    uint8_t  code;

    // Echo (128/129)
    bool     is_echo;
    uint16_t id;
    uint16_t seq;

    // Neighbor Discovery (135/136)
    bool     is_nd;
    struct in6_addr target;
};
struct arp_in
{
    bool present;
    uint16_t oper; // ответ или запрос
    uint8_t mac[MAC_LEN]; // МАС отправителя
    struct in_addr spa; // IP отправителя
    struct in_addr tpa; // IP получателя (цель)
};
struct packet {
    struct eth_in    eth;
    struct ipv4_in   ip4;
    struct ipv6_in   ip6;
    struct tcp_in    tcp;
    struct udp_in    udp;
    struct icmpv4_in icmpv4;
    struct icmpv6_in icmpv6;
    struct arp_in    arp;
};

// L2: Ethernet
#define RULE_HAS_SRC_MAC    (1U << 0)
#define RULE_HAS_DST_MAC    (1U << 1)
#define RULE_HAS_ETHERTYPE  (1U << 2)

// L3: IP
#define RULE_HAS_PROTO      (1U << 3)
#define RULE_HAS_SRC_IP     (1U << 4)
#define RULE_HAS_SRC_MASK   (1U << 5)
#define RELE_HAS_DST_MASK   (1U << 6)
#define RULE_HAS_DST_IP     (1U << 7)
#define RULE_HAS_TTL        (1U << 8)
#define RULE_HAS_IHL_RANGE  (1U << 9)

// L4: Порты и флаги
#define RULE_HAS_SRC_PORT   (1U << 10)
#define RULE_HAS_DST_PORT   (1U << 11)
#define RULE_HAS_TCP_FLAGS  (1U << 12)
// L4: флаги TCP
#define FLAG_HAS_SYN        (1U << 1)
#define FLAG_HAS_ACK        (1U << 2)
#define FLAG_HAS_FIN        (1U << 3)
#define FLAG_HAS_RST        (1U << 4)
#define FLAG_HAS_PSH        (1U << 5)
#define FLAG_HAS_URG        (1U << 6)
#define FLAG_HAS_ECE        (1U << 7)
#define FLAG_HAS_CWR        (1U << 8)


// L4: ICMP специфика
#define RULE_HAS_ICMP_TYPE  (1U << 13)
#define RULE_HAS_ICMP_CODE  (1U << 14)
#define RULE_HAS_ICMP_SIZE  (1U << 15)

// Резерв на будущее (v0.4+)
#define RULE_HAS_CONTENT    (1U << 16) // payload
#define RULE_HAS_DSIZE      (1U << 17) // Проверка размера payload
//L4: UDP
#define RULE_HAS_DATAGRAM   (1U << 18)

// Специальные служебные флаги
#define RULE_REQUIRES_IPV4  (1U << 30)
#define RULE_REQUIRES_IPV6  (1U << 31)

typedef struct { // сюда заносим из rules.txt
    uint64_t sid;
    uint32_t mask;
    char severity[8];
    
    // === L2: Ethernet ===
    unsigned char src_mac[6];
    unsigned char dst_mac[6];

    uint16_t ethertype;     // 0x0800, 0x0806, 0x86DD

    
    // === L3: IPv4 ===
    uint8_t  protocol;
    struct in_addr src_ip, src_mask;
    struct in_addr dst_ip, dst_mask;
    uint8_t  ttl_value;
    uint8_t  ihl_min, ihl_max;
   
    
    // === L4: TCP ===
    uint16_t src_port;
    uint16_t dst_port;

    uint8_t  tcp_flags;
    
    // === L4: UDP ===
    // (порты уже есть выше)
    uint32_t length_datagram;
    
    // === L4: ICMP ===
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    uint16_t icmp_size;

    // === Метаданные ===
    char     msg[64];
} rule_t;