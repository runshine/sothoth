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
#include <pthread.h>
#include <climits>

using namespace std;

extern char **environ; // 声明环境变量全局变量

void close_at_exec(int fd){
    int flags = fcntl(fd, F_GETFD);
    flags |= FD_CLOEXEC;
    fcntl(fd, F_SETFD, flags);
}

void close_all_fd(){
    int i = 0;
    for(i=3;i<4096;i++)
        close_at_exec(i);
}

bool endsWith(const std::string& str, const std::string& suffix) {
    if (str.length() < suffix.length())
        return false;
    return std::equal(suffix.rbegin(), suffix.rend(), str.rbegin());
}

std::string removeSuffix(const std::string& str, const std::string& suffix) {
    // 空后缀直接返回原字符串
    if (suffix.empty()) return str;

    // 检测后缀并截取
    if (endsWith(str, suffix)) {
        return str.substr(0, str.length() - suffix.length());
    }
    return str;  // 不匹配时返回原字符串
}


bool file_exist(std::string dir, std::string filename){
    if(access((dir + "/" + filename).data(),0)==0)
        return true;
    return false;
}

int restart_with_javaagent(std::vector<std::string> option_list) {
    bool restore_mode = false;
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
    char cwd[PATH_MAX] = {0};
    char exe[PATH_MAX] = {0};
    getcwd(cwd,sizeof(cwd));
    readlink("/proc/self/exe",exe,sizeof(exe));
    cout << "current dir: " << (char*)cwd << endl;
    cout << "exe: " << (char*)exe << endl;
    if(file_exist(cwd,args[0])){
        cout << "execute file is exist in current dir, use it again" << endl;
        new_args.push_back(args[0]); // 程序名
    }else {
        if(strcmp(exe,args[0].c_str()) == 0) {
            cout << "execute file is same with /proc/self/exe file, use exe directly" << endl;
            new_args.push_back(exe);
        }else if(endsWith(exe,args[0])){
            std::string folder =  removeSuffix(exe,args[0]);
            cout << "we are guess exe file work dir: "<< folder << endl;
            if(access(folder.data(),0)==0) {
                cout << "folder exist, start chdir to: " <<folder.data() << endl;
                chdir(removeSuffix(exe, args[0]).data());
                new_args.push_back(args[0]);
            }else{
                cout << "folder not exist, use exe directly" <<folder.data() << endl;
                new_args.push_back(exe);
            }
        }else{
            cout << "other sence, use exe directly" << endl;
            new_args.push_back(exe);
        }
    }

    for (size_t i = 0; i < option_list.size(); ++i) {
        if(option_list[i] == "--restore_mode") {
            restore_mode = true;
            break;
        }
    }

    if(!restore_mode) {
        cout << "current is inject agent mode" << endl;
        for (size_t i = 0; i < option_list.size(); ++i) {
            new_args.push_back(option_list[i]);
        }
        for (size_t i = 1; i < args.size(); ++i) {
            new_args.push_back(args[i]);
        }
    }else{
        cout << "current is restore agent mode" << endl;
        for (size_t i = 1; i < args.size(); ++i) {
            bool push_flag = true;
            for (size_t j = 0; j < option_list.size(); ++j) {
                if(option_list[j] == args[i]){
                    cout << "drop agent arg: " << option_list[j] << endl;
                    push_flag = false;
                    break;
                }
            }
            if(push_flag)
                new_args.push_back(args[i]);
        }
    }

    if(args.size() == new_args.size() && restore_mode){
        cout << "in restore mode we have no drop any options, ignore reboot" << endl;
        return NULL;
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

static string local_option_buf = "";

static void* restart_worker(void*){
    std::vector<std::string> option_list;
    sleep(5);
    option_list = splitArguments(local_option_buf);
    close_all_fd();
    restart_with_javaagent(option_list);
    return NULL;
}


JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *vm, char *options, void *reserved) {
    cout << "Agent_OnAttach, options: "<< options << endl;
    if(options != NULL) {
        local_option_buf = options;
    }else{
        local_option_buf = "";
    }
    pthread_t tid;
    pthread_create(&tid,NULL,restart_worker,NULL);
    cout << "Start new TID: " << tid <<endl;
    return JNI_OK;
}



JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {
    cout << "Agent_OnLoad" << endl;
    return JNI_OK;
}


JNIEXPORT void JNICALL Agent_OnUnload(JavaVM *vm) {
    cout << "Agent_OnUnload" << endl;
}

