#include "helper.hpp"
#include <string>
#include <iostream>
#include <jvmti.h>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <fstream>


using namespace std;

extern char **environ; // 声明环境变量全局变量

int restart_with_javaagent() {
    // 直接读取原始命令行参数（以\0分隔）
    std::ifstream cmdline("/proc/self/cmdline", std::ios::binary);
    if (!cmdline) {
        std::cerr << "Failed to open /proc/self/cmdline" << std::endl;
        return EXIT_FAILURE;
    }

    std::vector<char> buffer(
            (std::istreambuf_iterator<char>(cmdline)),
            std::istreambuf_iterator<char>()
    );
    cmdline.close();

    if (buffer.empty()) {
        std::cerr << "Failed to read command line arguments." << std::endl;
        return EXIT_FAILURE;
    }

    // 分割参数（保持原始格式）
    std::vector<std::string> args;
    std::vector<char*> argv_ptrs;
    char* start = buffer.data();
    for (char* p = buffer.data(); p < buffer.data() + buffer.size(); ++p) {
        if (*p == '\0') {
            if (p > start) { // 避免空字符串
                args.emplace_back(start);
            }
            start = p + 1;
        }
    }

    // 检查是否已存在目标参数
    const std::string agent_arg = "-javaagent:path/to/opentelemetry-javaagent.jar";
    bool agent_found = false;
    size_t agent_index = 0;

    for (size_t i = 1; i < args.size(); ++i) {
        if (args[i].find("-javaagent:") == 0) {
            if (args[i].find("opentelemetry-javaagent.jar") != std::string::npos) {
                agent_found = true;
                agent_index = i;
                break;
            }
        }
    }

    // 构建新参数列表
    std::vector<std::string> new_args;
    new_args.push_back(args[0]); // 程序名

    // 添加/替换agent参数
    if (agent_found) {
        for (size_t i = 1; i < args.size(); ++i) {
            new_args.push_back(i == agent_index ? agent_arg : args[i]);
        }
    } else {
        new_args.push_back(agent_arg);
        for (size_t i = 1; i < args.size(); ++i) {
            new_args.push_back(args[i]);
        }
    }

    // 准备execve参数数组
    std::vector<char*> exec_args;
    for (auto& arg : new_args) {
        exec_args.push_back(const_cast<char*>(arg.c_str()));
    }
    exec_args.push_back(nullptr);

    // 重新执行进程
    execve(exec_args[0], exec_args.data(), environ);

    // 如果执行失败
    perror("execve failed");
    return EXIT_FAILURE;
}


JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *vm, char *options, void *reserved) {
    cout << "Agent_OnAttach" << endl;
    restart_with_javaagent();
    return JNI_OK;
}



JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {
    cout << "Agent_OnLoad" << endl;
    return JNI_OK;
}


JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm) {
    cout << "Agent_OnUnload" << endl;
}

