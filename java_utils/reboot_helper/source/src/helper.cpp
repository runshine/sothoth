#include "helper.hpp"
#include <string>
#include <iostream>
#include <jvmti.h>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <fstream>
#include <fcntl.h>
#include <map>
#include <sstream>

using namespace std;

extern char **environ; // 声明环境变量全局变量

void close_at_exec(int fd){
    int flags = fcntl(fd, F_GETFD);
    flags |= FD_CLOEXEC;
    fcntl(fd, F_SETFD, flags);
}

void close_all_fd(){
    int i = 0;
    for(i=0;i<4096;i++)
        close_at_exec(i);
}

int restart_with_javaagent(std::map<std::string, std::string> option_map) {
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
    std::string agent_arg = "-javaagent:";
    bool agent_found = false;
    size_t agent_index = 0;
    if(option_map.find("sothoth_dir") != option_map.end()){
        agent_arg = agent_arg + option_map.find("sothoth_dir")->second + "/share/opentelemetry-javaagent.jar";
    }else{
        fprintf(stderr, "use sothoth_dir with default dir: %s\n","/sothothv2");
        agent_arg = agent_arg + "/sothothv2" + "/share/opentelemetry-javaagent.jar";
    }

    if(access(agent_arg.c_str(),O_RDONLY) != 0){
        fprintf(stderr, "failed access opentelemetry-javaagent.jar: %s\n",agent_arg.c_str());
        return EXIT_FAILURE;
    }

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

// 辅助函数：去除字符串两端的空白字符
std::string trim(const std::string& str) {
    const char* whitespace = " \t\n\r\f\v";
    size_t start = str.find_first_not_of(whitespace);
    if (start == std::string::npos) return ""; // 全空白字符串

    size_t end = str.find_last_not_of(whitespace);
    return str.substr(start, end - start + 1);
}

// 主解析函数
std::map<std::string, std::string> parseOptions(const std::string& input) {
    std::map<std::string, std::string> options;
    std::istringstream ss(input);
    std::string token;

    // 按逗号分割键值对
    while (std::getline(ss, token, ',')) {
        // 查找等号位置
        size_t eq_pos = token.find('=');
        if (eq_pos == std::string::npos) continue; // 跳过无效格式

        // 分割键和值
        std::string key = trim(token.substr(0, eq_pos));
        std::string value = trim(token.substr(eq_pos + 1));

        // 跳过空键
        if (key.empty()) continue;

        // 存储到map
        options[key] = value;
    }

    return options;
}

JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *vm, char *options, void *reserved) {
    cout << "Agent_OnAttach, options: "<< options << endl;
    std::map<std::string, std::string> option_map;
    if(options != NULL)
        parseOptions(options);
    close_all_fd();
    restart_with_javaagent(option_map);
    return JNI_OK;
}



JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {
    cout << "Agent_OnLoad" << endl;
    return JNI_OK;
}


JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm) {
    cout << "Agent_OnUnload" << endl;
}

