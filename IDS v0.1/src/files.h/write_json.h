#pragma once
#include <stdio.h>
#include <arpa/inet.h>
#include "structures.h"

void write_json(FILE* f, struct packet* pkt);

