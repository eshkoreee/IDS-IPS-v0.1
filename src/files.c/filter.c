#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "structures.h"
#include "load_rules.h"

// протоколы
#include <netinet/in.h>

/*
в этом файле будет реализована логика многоуровневой проверки
с использованием правил загруженых в load_rules.c.
*/

bool check_packet(struct packet* pkt, FILE* rules_file, rule_t* rules)// тут список rules уже есть
{
    
}
