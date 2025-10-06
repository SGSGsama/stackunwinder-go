仿着stackplz随便写写的，目前只实现了一点点功能，只打算支持arm64架构


## 环境配置

1. 复制环境配置模板：

```bash
cp env.sh.example env.sh
```

2. 编辑 env.sh 设置你的本地路径
3. 加载环境变量：
source env.sh
4. 开始编译：
make

### 构建

先去把makefile上面一整排的路径换成自己的，然后再把unwindstack这个库的静态库构建好
然后在src目录`make app`即可，如果有问题就`make clean`再重试，vscode飘红可以尝试regenerate cgo definition

然后应该会生成stackHelp.so,在运行时需要`libc++_shared.so`和`stackHelp.so`位于stackunwinder-go可执行文件同一文件夹下，libc++的动态库可以在安卓ndk里找到