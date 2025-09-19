#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
int main() {
  printf("Press Enter to continue...\n");
  getchar();
  int fd = syscall(0x38, AT_FDCWD, "./test.txt", O_CREAT | O_RDWR, 0644);
  if (fd == -1) {
    perror("open failed");
    return 1;
  }
  //   write(fd, "Hello, World!\n", 14);
  syscall(0x40, fd, "test1\n", 6);
  syscall(0x40, fd, "test2\n", 6);
  syscall(0x40, fd, "test3\n", 6);
  syscall(0x40, fd, "test4\n", 6);
  syscall(0x40, fd, "test5\n", 6);
  syscall(0x40, fd, "test6\n", 6);
  syscall(0x40, fd, "test7\n", 6);
  syscall(0x40, fd, "test8\n", 6);
  syscall(0x40, fd, "test9\n", 6);
  close(fd);
  return 0;
}