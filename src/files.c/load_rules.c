
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "structures.h"
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <arpa/inet.h>


#define MAX_TOKENS  32
#define MAX_LEN_TOKEN 256

typedef enum 
{
    INSIDE_TOKEN,
    OUTSIDE_TOKEN,
    INSIDE_QUOTES
} State;

static void push_in_rule(char* key, char* value, rule_t* rules);


static char tokens[MAX_TOKENS][MAX_LEN_TOKEN] = {0};// один сценарий
// Добавляем параметр out_count, чтобы вызывающая функция знала, сколько токенов найдено
static bool tokenize(FILE* rules_file, int* out_count)
{
    char rule[4096] = {0};
    
    if (fgets(rule, sizeof(rule), rules_file) != NULL) {
        rule[strcspn(rule, "\n\r")] = '\0';
    } else {
        return true;
    }

    int counter_rule = 0;
    int counter_len = 0;
    State STATE = OUTSIDE_TOKEN;

    for(int counter = 0; rule[counter] != '\0'; counter++) 
    {
        char symbol = rule[counter];


        if (counter_rule >= MAX_TOKENS) {
            fprintf(stderr, "Warning: Too many tokens in rule, truncated.\n");
            break; 
        }

        if(STATE == OUTSIDE_TOKEN)
        {
            if(symbol == ' ' || symbol == '\t') continue;
            else 
            {
                STATE = INSIDE_TOKEN;
                tokens[counter_rule][counter_len++] = symbol;
            } 
        }
        else if(STATE == INSIDE_TOKEN)
        {
            if(symbol == '"') 
            {
                STATE = INSIDE_QUOTES;
                tokens[counter_rule][counter_len++] = symbol;
            }
            else if(symbol == ' ' || symbol == '\t')
            {
                tokens[counter_rule][counter_len] = '\0';
                counter_len = 0;
                counter_rule++;
                STATE = OUTSIDE_TOKEN;
            }
            else
            {
                if (counter_len < MAX_LEN_TOKEN - 1) {
                    tokens[counter_rule][counter_len++] = symbol;
                }
            }
        }
        else if(STATE == INSIDE_QUOTES)
        {
            if (counter_len < MAX_LEN_TOKEN - 1) {
                tokens[counter_rule][counter_len++] = symbol;
            }
            
            if (symbol == '"') {
                STATE = INSIDE_TOKEN; // Вышли из кавычек
            }
        }
    }

    // Он завершает самый последний токен в строке если он не закончился пробелом
    if (counter_len > 0 && counter_rule < MAX_TOKENS) {
        tokens[counter_rule][counter_len] = '\0';
        counter_rule++;
    }

    *out_count = counter_rule; //возвращаем количество найденных токенов
    return true;
}
static bool parse_tokens(int out_count, rule_t* rules)
{
    for(int i = 0; i < out_count; i++)
    {

        char *eq = strchr(tokens[i], '=');

        if (eq == NULL) continue;
        
        *eq = '\0';  // разрезаем токен
        char *key = tokens[i];      // всё до '=' key = key\0value\0
        char *value = eq + 1;       // всё после '=' value = value\0
        size_t vlen = strlen(value);
        if (vlen > 2 && value[0] == '"' && value[vlen - 1] == '"') 
        {
        value[vlen - 1] = '\0'; // Ставим конец строки вместо закрывающей кавычки
        value++;                // Сдвигаем указатель на 1 байт вперед, пропуская открывающую кавычку
        }

        push_in_rule(key, value, rules);
    }
    return true;
}

static void push_in_rule(char* key, char* value, rule_t* rules)
{
    if(strcmp(key, "sid") == 0) {rules->sid = (uint32_t)strtoul(value, NULL, 10); rules->msg[sizeof(rules->msg) - 1] = '\0';}
    else if(strcmp(key, "severity") == 0) {strncpy(rules->severity, value, sizeof(rules->severity) - 1); rules->severity[sizeof(rules->severity) - 1] = '\0';} // strncpy для строк

    else if(strcmp(key, "msg") == 0) {strncpy(rules->msg, value, sizeof(rules->msg) - 1);  rules->msg[sizeof(rules->msg) - 1] = '\0';}
    
    else if(strcmp(key, "src_mac") == 0) 
    {
        // %hhx читает 1 байт как hex. Возвращает количество успешно прочитанных элементов.
        if (sscanf(value, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
                &rules->src_mac[0], &rules->src_mac[1], &rules->src_mac[2],
                &rules->src_mac[3], &rules->src_mac[4], &rules->src_mac[5]) == 6) 
        {
            rules->mask |= RULE_HAS_SRC_MAC;
        }
        else {
            fprintf(stderr, "WARNING: invalid MAC address format: %s\n", value);
        }
    }
    else if(strcmp(key, "dst_mac") == 0) 
    {
    // %hhx читает 1 байт как hex. Возвращает количество успешно прочитанных элементов.
        if (sscanf(value, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
                &rules->dst_mac[0], &rules->dst_mac[1], &rules->dst_mac[2],
                &rules->dst_mac[3], &rules->dst_mac[4], &rules->dst_mac[5]) == 6) 
        {
            rules->mask |= RULE_HAS_DST_MAC;
        }
        else {
            fprintf(stderr, "WARNING: invalid MAC address format: %s\n", value);
        }
    }
    else if(strcmp(key, "ethertype") == 0)
    {
        rules->ethertype = (uint16_t)strtoul(value, NULL, 16);
        rules->mask |= RULE_HAS_ETHERTYPE;
    }
    else if(strcmp(key, "src_ip") == 0)// найди маску
    {
        char* slash = strchr(value, '/');

        if(slash != NULL)
        {
            *slash = '\0';
            char* mask_str = slash + 1; // "24"
            uint32_t mask_bits = (uint32_t)strtoul(mask_str, NULL, 10);
            // Маска /24 = 0xFFFFFF00, /16 = 0xFFFF0000 и т.д.
            rules->src_mask.s_addr = htonl(~((1U << (32 - mask_bits)) - 1));
        }
        else rules->src_mask.s_addr = 0xFFFFFFFF;

        if(inet_pton(AF_INET, value, &rules->src_ip) != 1)
        {
            fprintf(stderr, "Warning: Invalid IP address: %s\n", value);
            return;
        }
        else rules->mask |= RULE_HAS_SRC_IP;
    }
    else if(strcmp(key, "dst_ip") == 0)
    {
        char* slash = strchr(value, '/');

        if(slash != NULL)
        {
            *slash = '\0';
            char* mask_str = slash + 1; // "24"
            uint32_t mask_bits = (uint32_t)strtoul(mask_str, NULL, 10);
            // Маска /24 = 0xFFFFFF00, /16 = 0xFFFF0000 и т.д.
            rules->dst_mask.s_addr = htonl(~((1U << (32 - mask_bits)) - 1));
        }
        else rules->dst_mask.s_addr = 0xFFFFFFFF;

        if(inet_pton(AF_INET, value, &rules->dst_ip) != 1)
        {
            fprintf(stderr, "Warning: Invalid IP address: %s\n", value);
            return;
        }
        else rules->mask |= RULE_HAS_DST_IP;
    }
    else if(strcmp(key, "proto") == 0)
    {
        if(strcasecmp(value, "TCP") == 0) rules->protocol = 6;
        else if(strcasecmp(value, "UDP") == 0) rules->protocol = 17;
        else if(strcasecmp(value, "ICMP") == 0) rules->protocol = 1;
        else if(strcasecmp(value, "IGMP") == 0) rules->protocol = 2;
        else if(strcasecmp(value, "IPv6") == 0) rules->protocol = 42; // инкапсуляция IPv6 внутри IPv4
        else if(strcasecmp(value, "GRE") == 0) rules->protocol = 47;
        else if(strcasecmp(value, "ESP") == 0) rules->protocol = 50;
        else if(strcasecmp(value, "AH") == 0) rules->protocol = 51;
        else if(strcasecmp(value, "OSPF") == 0) rules->protocol = 89;
        else if(strcasecmp(value, "SCTP") == 0) rules->protocol = 132;
        rules->mask |= RULE_HAS_PROTO;
        
    }
    else if(strcmp(key, "ttl") == 0)
    {
        rules->ttl_value = (uint8_t)strtoul(value, NULL, 10);
        rules->mask |= RULE_HAS_TTL;
    }
    else if(strcmp(key, "ihl_min") == 0)
    {
        rules->ihl_min = (uint8_t)strtoul(value, NULL, 10);
    }
    else if(strcmp(key, "ihl_max") == 0)
    {
        rules->ihl_max = (uint8_t)strtoul(value, NULL, 10);
    }
    else if(strcmp(key, "sport") == 0) 
    {
        
        uint32_t temp_port = strtoul(value, NULL, 10);
        if (temp_port > 65535) {
            fprintf(stderr, "WARNING: invalid source port %s\n", value);
            return;
        }
        rules->src_port = (uint16_t)temp_port;
        rules->mask |= RULE_HAS_SRC_PORT;

    }
    else if(strcmp(key, "dport") == 0) 
    {
        
        uint32_t temp_port = strtoul(value, NULL, 10);
        if (temp_port > 65535) {
            fprintf(stderr, "WARNING: invalid destination port %s\n", value);
            return;
        }
        rules->dst_port = (uint16_t)temp_port;
        rules->mask |= RULE_HAS_DST_PORT;

    }
    else if(strcmp(key, "flags") == 0)
    {
        for(int i = 0; value[i] != '\0'; i++)
        {
            if(value[i] == ',' || value[i] == ' ' || value[i] == '|') continue;
            else
            {
                switch(value[i])
                {
                    case 'S':
                    rules->tcp_flags |= FLAG_HAS_SYN;
                    rules->mask |= RULE_HAS_TCP_FLAGS;
                        break;

                     case 'A':
                    rules->tcp_flags |= FLAG_HAS_ACK;
                    rules->mask |= RULE_HAS_TCP_FLAGS;
                        break;

                     case 'F':
                    rules->tcp_flags |= FLAG_HAS_FIN;
                    rules->mask |= RULE_HAS_TCP_FLAGS;
                        break;

                    case 'R':
                    rules->tcp_flags |= FLAG_HAS_RST;
                    rules->mask |= RULE_HAS_TCP_FLAGS;
                        break;

                     case 'P':
                    rules->tcp_flags |= FLAG_HAS_PSH;
                    rules->mask |= RULE_HAS_TCP_FLAGS;
                        break;

                     case 'U':
                    rules->tcp_flags |= FLAG_HAS_URG;
                    rules->mask |= RULE_HAS_TCP_FLAGS;
                        break;

                    case 'E':
                    rules->tcp_flags |= FLAG_HAS_ECE;
                    rules->mask |= RULE_HAS_TCP_FLAGS;
                        break;

                     case 'C':
                    rules->tcp_flags |= FLAG_HAS_CWR;
                    rules->mask |= RULE_HAS_TCP_FLAGS;
                        break;

                    default:
                    fprintf(stderr, "WARNING: unknown TCP flag %c", value[i]);
                        break;
                }
            }
        }
    }
    else if(strcmp(key, "length_datagram") == 0)
    {
        int length = (uint32_t)strtoul(value, NULL, 10); 
        if(length <= 0)
        {
            perror("length_datagram");
            return;
        }
        else
        {
            rules->length_datagram = length;
            rules->mask |= RULE_HAS_DATAGRAM;
        }
    }
    else if(strcmp(key, "type") == 0)
    {
        int type = (uint8_t)strtoul(value, NULL, 10);
        rules->icmp_type = type;
        rules->mask |= RULE_HAS_ICMP_TYPE;
    }
    else if(strcmp(key, "code") == 0)
    {
        int code = (uint8_t)strtoul(value, NULL, 10);
        rules->icmp_code = code;
        rules->mask |= RULE_HAS_ICMP_CODE;
    }
    else if(strcasecmp(key, "ICMP_size") == 0)
    {
        int size = (uint16_t)strtoul(value, NULL, 10);
        if(size <= 0)
        {
            perror("icmp_size");
            return;
        }
        else
        {
            rules->icmp_size = size;
            rules->mask |= RULE_HAS_ICMP_SIZE;
        }
    }
}


/*
этот метод отвечает за загрузку файлов из файла rules_full-Match.txt 
с последующим заносом в массив структур rules. находится в стадии 
разработки и как временная мера вся логика реализована через if else.
в будущем логика будет заменена на хеш таблицы
*/

bool load_rules(FILE* rules_file, rule_t* rules, size_t count)
{
    bool parse_result = false;
    for(size_t i = 0; i < count; i++)
    {
        int out_count = 0;
        bool tokenize_result = tokenize(rules_file, &out_count);
        if(tokenize_result == false) return false;
        parse_result = parse_tokens(out_count, rules + i);
    }
    return parse_result;
}
