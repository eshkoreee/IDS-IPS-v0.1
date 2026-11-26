#pragma once

#include <stdio.h>
#include "structures.h"
#include <stdint.h>

bool load_rules(FILE* rules_file, rule_t* rules, size_t count);