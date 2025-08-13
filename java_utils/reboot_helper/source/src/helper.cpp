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

int restart_with_javaagent(std::vector<std::string> option_list) {
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

    // 构建新参数列表
    std::vector<std::string> new_args;
    new_args.push_back(args[0]); // 程序名

    for (size_t i = 0; i < option_list.size(); ++i) {
        new_args.push_back(option_list[i]);
    }

    for (size_t i = 1; i < args.size(); ++i) {
        new_args.push_back(args[i]);
    }

    // 准备execve参数数组
    std::vector<char*> exec_args;
    for (auto& arg : new_args) {
        exec_args.push_back(const_cast<char*>(arg.c_str()));
    }
    exec_args.push_back(nullptr);

    std::cout << "Executing with arguments:\n";
    for (char** arg = exec_args.data(); *arg != nullptr; ++arg) {
        std::cout << "  " << *arg << "\n";
    }
    std::cout << std::flush; // 确保在execve前刷新输出

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

std::vector<std::string> splitArguments(const std::string& input) {
    std::vector<std::string> tokens;
    bool inSingleQuote = false;
    bool inDoubleQuote = false;
    std::string token;

    for (size_t i = 0; i < input.length(); ++i) {
        char c = input[i];

        if (c == '\'' && !inDoubleQuote) {
            inSingleQuote = !inSingleQuote;
        } else if (c == '"' && !inSingleQuote) {
            inDoubleQuote = !inDoubleQuote;
        } else if (std::isspace(static_cast<unsigned char>(c))) {
            if (inSingleQuote || inDoubleQuote) {
                token += c;
            } else {
                if (!token.empty()) {
                    tokens.push_back(token);
                    token.clear();
                }
            }
        } else {
            token += c;
        }
    }

    if (!token.empty()) {
        tokens.push_back(token);
    }

    return tokens;
}


JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *vm, char *options, void *reserved) {
    cout << "Agent_OnAttach, options: "<< options << endl;
    std::vector<std::string> option_list;
    if(options != NULL)
        option_list = splitArguments(options);
    close_all_fd();
    restart_with_javaagent(option_list);
    return JNI_OK;
}



JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {
    cout << "Agent_OnLoad" << endl;
    return JNI_OK;
}


JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm) {
    cout << "Agent_OnUnload" << endl;
}

