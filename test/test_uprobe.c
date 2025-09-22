#include "stdio.h"
int add(int a, int b) { return a + b; }
int sub(int a, int b) { return a - b; }
int main() {
  int a = 10, b = 5;
  printf("Press Enter to continue...\n");
  getchar();
  printf("add: %d + %d = %d\n", a, b, add(a, b));
  printf("sub: %d - %d = %d\n", a, b, sub(a, b));
  return 0;
}