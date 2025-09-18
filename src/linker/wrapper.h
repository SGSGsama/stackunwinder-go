#pragma once
#include <stdbool.h>
#include <stdint.h>
void setupLibEnv(char *dl_path);
void test_CGO(int a);
struct Data {
  uint64_t regs[31];
  uint64_t sp;
  uint64_t pc;
  char stackData[65536];
  uint64_t stackSize;
};
char *unwind_Online(int pid, struct Data *data);
// void unwind_Offline(int pid, struct Data *data);
void free_resPtr(char *ptr);