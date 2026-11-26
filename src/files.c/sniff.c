// Sniff.c
// Стандартные
#include <stdio.h>
#include <stdlib.h>

// Сеть и сокеты
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Утилиты
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <ifaddrs.h>
#include <signal.h>

// Локальные
#include "structures.h"
#include "write_json.h"
#include "parse.h"
#include "filter.h"
#include "load_rules.h"

volatile sig_atomic_t stop_flag = 0;

static char* get_interface()
{
    struct ifaddrs* list_inter = NULL;
    int rc = getifaddrs(&list_inter);
    if(rc == -1){ perror("get_interface"); return NULL; }
    unsigned int required = IFF_UP | IFF_RUNNING;
    for( struct ifaddrs* it = list_inter; it != NULL; it = it->ifa_next)
    {
        if(((it->ifa_flags & required) == required) && !(it->ifa_flags & IFF_LOOPBACK))
        {
            char* name = strdup(it->ifa_name);
            freeifaddrs(list_inter);
            return name;
        }
    }
    freeifaddrs(list_inter);
    return NULL;
}

static int get_index()
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    char* interface = get_interface();
    if(interface == NULL) {perror("interface"); return -1;}
    
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);  // временный сокет для ioctl

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl");
        close(sockfd);
        free(interface);
        return -1;
    }
    int ifindex = ifr.ifr_ifindex;
    close(sockfd);
    free(interface);
    return ifindex;
}

static void sigint_handle(int sig)
{
    (void)sig;
    stop_flag = 1;
}

static int sniff(FILE* f, FILE* rules_file, rule_t* rules, int sock)
{
    struct packet pkt = {0}; // ИСПРАВИТЬ объявление при каждой итерации
    unsigned char buffer[65536 + 64]; // ИСПРАВИТЬ
    ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
    if (len <= (ssize_t)66) return 0;
    if (len < 0 || len < (ssize_t)sizeof(struct ethhdr))
    {
    perror("recvfrom");
    return -1;
    }
  
    parse_ether(&pkt, buffer, len);
    if(!pkt.eth.present) return 0;
    
    int ethproto = pkt.eth.ethertype;
    switch(ethproto)
    {
        case ETH_P_IPV4:
        {
            const uint8_t* l3 = buffer + ETH_LEN;
            size_t l3len = (size_t)len - ETH_LEN;
            if (l3len < sizeof(struct iphdr)) break;

            parse_ipv4(&pkt, l3, l3len);

            if (!pkt.ip4.present || pkt.ip4.ihl < 5 || (size_t)(pkt.ip4.ihl * 4) > l3len) break;
            const uint8_t* l4 = l3 + pkt.ip4.ihl * 4;
            size_t l4len = l3len - pkt.ip4.ihl * 4;
            switch(pkt.ip4.protocol)
            {
                case 1:  parse_icmpv4(&pkt, l4, l4len);      break;
                case 6:  parse_tcp (&pkt, l4, l4len);        break;
                case 17: parse_udp (&pkt, l4, l4len);        break;
                default: printf("UNKNOWN PROTOCOL");         break;
            }
            break;
        }
        case ETH_P_IPV6:
        {
            parse_ipv6(&pkt, buffer + ETH_LEN, (size_t)len - ETH_LEN);

            if (!pkt.ip6.present || (size_t)(len - ETH_LEN) < IPV6HDR_len) break;

            const uint8_t* l4 = buffer + ETH_LEN + IPV6HDR_len;
            size_t l4len = (size_t)len - ETH_LEN - IPV6HDR_len;

            switch(pkt.ip6.nexthdr)
            {
                case 58:  parse_icmpv6(&pkt, l4, l4len);     break;
                case 6:  parse_tcp (&pkt, l4, l4len);        break;
                case 17: parse_udp (&pkt, l4, l4len);        break;
                default: printf("UNKNOWN HEADER\n");         break;
            }
            break;
        }
        case ETH_P_ARP:
        {
            parse_arp(&pkt, buffer + ETH_LEN, (size_t)len - ETH_LEN);
                break;
        }
        default:
            printf("UNKNOWN OR EMPTY PACKET\n");
        break;
    }

    sigset_t block_set, old_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGINT);
    sigprocmask(SIG_BLOCK, &block_set, &old_set);

    if(check_packet(&pkt, rules_file, rules)) write_json(f, &pkt);
   
   
    sigprocmask(SIG_SETMASK, &old_set, NULL);
    return 0;
}

/*
движок сниффера и диспетчер отправки пакетов в нужные методы разбиения байтов.
здесь пакеты попадают в буффер которые в следствии заносятся в структуру packet методами 
с приставкой parse_*. логика парса или вывода IPv6 временно сломана и находится в процессе правки
все структуры и макросы которые вы увидите в программе находяться в files.h/structures.h.
в моей IDE intellisense часто ругается на структуры в этом файле просьба не обращать
внимания это баг intellisense
*/

int main(void)
{   
    printf("Программа запущена от пользователя: %s\n", getlogin());
    printf("UID: %d\n", getuid());
    printf("EUID: %d\n", geteuid());

    signal(SIGINT, sigint_handle);   // Ctrl+C
    signal(SIGTERM, sigint_handle);  // kill

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    int rcvbuf = 4 * 1024 * 1024; // 4 МБ
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    if(sock < 0)
    {
        perror("socket");
        return 1;
    }

    int isindex = get_index();
    if (isindex < 0) return 1;
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = isindex;

    if(bind(sock, (struct sockaddr*)&sll, sizeof(sll)) == -1)
    {
        perror("bind sock");
        return -1;
    }
    
    FILE* log = fopen("logs/log.ndjson", "w");
    FILE* rules_file = fopen("wordlists/rules_full-Match.txt", "r");
    if(!rules_file)
    {
        perror("rules_full-Match");
        return 1;
    }
    rule_t rules[1024] = {0};
    bool result = load_rules(rules_file, rules, sizeof(rules) / sizeof(rules[0]));
    if(result == false) {perror("load_rules"); return 1;}
    if (!log) { perror("fopen"); return 1;}

    char* buf = malloc(1024 * 1024);
    setvbuf(log, buf, _IOFBF, 1024 * 1024);

    
    while(!stop_flag)
    {
        int res = sniff(log, rules_file, rules, sock);
        if (res == -1) return 1;
    }
    system("clear");
    printf("stopping...");
    fflush(log);
    off_t pos = ftello(log);
    if (ftruncate(fileno(log), pos - 1) == -1) perror("ftruncate");
    fseeko(log, pos - 1, SEEK_SET);
    fputc('}', log);
    free(buf);
    fclose(log);
    return 0;
}
