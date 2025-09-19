#include <stdio.h>
#include <unistd.h>
void func3() { printf("test func3\n"); }
void func2() {
  func3();
  printf("test func2\n");
}
void func1() {
  func2();
  printf("test func1\n");
}

int main() {
  while (1) {
    func1();
    sleep(5);
  }
}

// 7fe89bc000-7fe89de000 rw-p 00000000 00:00 0 [stack]
// func3  sp 7fe89db390
// func2  sp 7fe89db3a0
// func1  sp 7fe89db380