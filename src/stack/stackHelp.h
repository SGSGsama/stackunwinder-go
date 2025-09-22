#pragma once
#include <stdint.h>
typedef struct Data {
  uint64_t regs[31];
  uint64_t sp;
  uint64_t pc;
} Data;
extern "C" {
void unwind_Offline(int pid, Data *data);
char *unwind_Online(int pid, Data *data);
void test_CGO(int a);
}