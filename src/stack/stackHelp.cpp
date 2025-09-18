#include "stackHelp.h"
#include "unwindstack/Arch.h"
#include "unwindstack/Regs.h"
#include "unwindstack/UserArm64.h"
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdio.h>
#include <string>
#include <sys/resource.h>
#include <time.h>
#include <unwindstack/AndroidUnwinder.h>
#include <unwindstack/MachineArm64.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/RegsArm64.h>
#include <unwindstack/Unwinder.h>
class CustomAndroidRemoteUnwinder : public unwindstack::AndroidRemoteUnwinder {
public:
  CustomAndroidRemoteUnwinder(pid_t pid) : AndroidRemoteUnwinder(pid) {}
  void setArch(unwindstack::ArchEnum arch) { arch_ = arch; }
  void setMaxFrames(size_t max_frames) { max_frames_ = max_frames; }

protected:
  bool InternalInitialize(unwindstack::ErrorData &error) override {
    // arch要调用ptrace，和SIGSTOP会冲突，所以我们手动设置arch
    // 下面的照抄即可
    maps_.reset(new unwindstack::RemoteMaps(pid_));
    if (!maps_->Parse()) {
      error.code = unwindstack::ERROR_MAPS_PARSE;
      return false;
    }

    if (process_memory_ == nullptr) {
      process_memory_ = unwindstack::Memory::CreateProcessMemoryCached(pid_);
    }
    return true;
  }
};
unwindstack::Regs *prepareReg(Data *data) {
  unwindstack::arm64_user_regs arm64_user_regs;
  memset(&arm64_user_regs, 0, sizeof(arm64_user_regs));
  memcpy(&arm64_user_regs.regs, &data->regs, sizeof(data->regs));
  arm64_user_regs.sp = data->sp;
  arm64_user_regs.pc = data->pc;
  auto regs = static_cast<unwindstack::RegsArm64 *>(
      unwindstack::RegsArm64::Read(&arm64_user_regs));
  regs->SetPACMask(0);
  return regs;
}
std::string readFileToString(const std::string &filePath) {
  std::ifstream inputFile(filePath);
  if (!inputFile.is_open()) {

    return ""; // 返回空字符串表示失败。
  }
  // 3. 创建一个字符串流（stringstream）对象。
  std::stringstream buffer;
  buffer << inputFile.rdbuf();
  return buffer.str();
}
extern "C" {
// 离线栈回溯，不需要中断执行，使用bpf中dump的栈数据，可能出现截断现象，感觉有点sb，不如在线的一根
void unwind_Offline(int pid, Data *data) {

  std::unique_ptr<unwindstack::Regs> unwind_regs(prepareReg(data));
  // std::cout << "arch: " << (int)unwind_regs->Arch() << "\n";
  if (unwind_regs == NULL) {
    fprintf(stderr, "Failed to prepare registers\n");
    return;
  }
  std::shared_ptr<unwindstack::Memory> stack =
      unwindstack::Memory::CreateOfflineMemory(
          reinterpret_cast<uint8_t *>(data->stackData), data->sp,
          data->sp + data->stackSize);
  std::string mapsBuffer;
  std::unique_ptr<unwindstack::Maps> maps;
  std::string mapsPath = "/proc/" + std::to_string(pid) + "/maps";
  mapsBuffer = readFileToString(mapsPath);
  // std::cout << mapsBuffer << "\n";
  if (mapsBuffer == "") {
    fprintf(stderr, "Failed to read maps file: %s\n", mapsPath.c_str());
    return;
  }
  maps.reset(new unwindstack::BufferMaps(mapsBuffer.c_str()));
  maps->Parse();
  unwindstack::Unwinder unwinder(512, maps.get(), unwind_regs.get(), stack);
  unwinder.Unwind();
  for (size_t i = 0; i < unwinder.NumFrames(); i++) {
    printf("%s\n", unwinder.FormatFrame(i).c_str());
  }
}
// 在线栈回溯，实时采样栈数据，需要中断执行防止上下文变化
char *unwind_Online(int pid, Data *data) {
  std::unique_ptr<unwindstack::Regs> unwind_regs(prepareReg(data));
  // std::cout << "arch: " << (int)unwind_regs->Arch() << "\n";
  if (unwind_regs == NULL) {
    fprintf(stderr, "Failed to prepare registers\n");
    return nullptr;
  }
  CustomAndroidRemoteUnwinder unwinder(pid);
  unwinder.setArch(unwindstack::ARCH_ARM64);
  unwindstack::ErrorData error;
  if (!unwinder.Initialize(error)) {
    fprintf(stderr, "Failed to initialize unwinder: %d\n", error.code);
    return nullptr;
  }
  unwindstack::AndroidUnwinderData result;
  if (!unwinder.Unwind(unwind_regs.get(), result)) {
    fprintf(stderr, "Failed to unwind: %d\n", result.error.code);
    return nullptr;
  }
  std::string resultStr;
  for (const auto &frame : result.frames) {
    resultStr += unwinder.FormatFrame(frame) + '\n';
  }
  char *res = (char *)malloc(resultStr.length() + 1);
  if (res == nullptr) {
    return nullptr;
  }
  strcpy(res, resultStr.c_str());
  return res;
}
void test_CGO(int a) { std::cout << "test : " << a << "\n"; }
}
