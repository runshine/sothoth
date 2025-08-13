cmake_minimum_required(VERSION 3.5.0)
project(reboot_helper CXX)

SET(CMAKE_CXX_STANDARD 11)
SET(CMAKE_BUILD_TYPE "Release")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall -Ofast")
set(CMAKE_VERBOSE_MAKEFILE True)

set(REBOOT_HELPER_SOURCE src/helper.cpp)
add_library(reboot_helper SHARED ${REBOOT_HELPER_SOURCE})
target_include_directories(reboot_helper PRIVATE ${PROJECT_SOURCE_DIR}/include)

file(GLOB_RECURSE JVMTI_H_PATHS "/usr/**/jvmti.h")
if (JVMTI_H_PATHS)
    # 这里我们取第一个找到的路径
    list(GET JVMTI_H_PATHS 0 JVMTI_H_PATH)
    get_filename_component(JVMTI_INCLUDE_DIR ${JVMTI_H_PATH} DIRECTORY)
    message(STATUS "Found jvmti.h at ${JVMTI_H_PATH} --> ${JVMTI_INCLUDE_DIR}")
    target_include_directories(reboot_helper
            PRIVATE ${JVMTI_INCLUDE_DIR}
            PRIVATE ${JVMTI_INCLUDE_DIR}/linux
            )
else()
    message(FATAL_ERROR "jvmti.h not found in /usr")
endif()


install(TARGETS reboot_helper
        LIBRARY DESTINATION ${PROJECT_SOURCE_DIR}/dist/lib  # 动态库安装路径
        ARCHIVE DESTINATION ${PROJECT_SOURCE_DIR}/dist/lib  # 静态库安装路径
        RUNTIME DESTINATION ${PROJECT_SOURCE_DIR}/dist/bin  # 可执行文件安装路径
        PUBLIC_HEADER DESTINATION ${PROJECT_SOURCE_DIR}/dist/include  # 头文件安装路径
)