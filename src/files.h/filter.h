#pragma once

#include "structures.h"


bool check_packet(struct packet* pkt, FILE* rules_file, rule_t* rules);