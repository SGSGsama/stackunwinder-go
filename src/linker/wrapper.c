#include "wrapper.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef void (*testPtr)(int);
testPtr _test_CGO = NULL;

typedef char *(*unwindPtr)(int, struct Data *);
// unwindPtr _unwind = NULL;
unwindPtr _unwindOnline = NULL;

static bool isDebug = false;
void *loadingLibs(const char *dirPath, const char *soName) {
  char full_path[256];
  snprintf(full_path, sizeof(full_path), "%s/%s", dirPath, soName);
  if (isDebug) {
    printf("loading :%s\n", full_path);
  }
  void *handle = dlopen(full_path, RTLD_NOW);
  if (handle == NULL) {
    printf("Error loading %s: %s\n", soName, dlerror());
    exit(EXIT_FAILURE);
  }
  return handle;
}

void setupLibEnv(char *exePath) {

  isDebug = getenv("STACKUNWINDER_DEBUG") != NULL &&
            (strcmp(getenv("STACKUNWINDER_DEBUG"), "1") ==
             0);                            // check if debug mode is enabled
  loadingLibs(exePath, "libc++_shared.so"); // load libc++_shared.so
  void *stackHelpHandle = loadingLibs(
      exePath, "stackHelp.so"); // load libstackHelp.so for stack unwind
  _test_CGO = (testPtr)dlsym(stackHelpHandle, "test_CGO");
  // _unwind = (unwindPtr)dlsym(stackHelpHandle, "unwind_Offline");
  _unwindOnline = (unwindPtr)dlsym(stackHelpHandle, "unwind_Online");
}

void test_CGO(int a) { (*_test_CGO)(a); }
// void unwind_Offline(int pid, struct Data *data) { (*_unwind)(pid, data); }
void free_resPtr(char *ptr) { free(ptr); }
char *unwind_Online(int pid, struct Data *data) {
  return (*_unwindOnline)(pid, data);
}