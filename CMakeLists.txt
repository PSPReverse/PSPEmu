cmake_minimum_required(VERSION 3.9)

project(PSPEmu VERSION 0.0.0 DESCRIPTION "PSP emulator")

set(CMAKE_THREAD_PREFER_PTHREAD On)
find_package (Threads)
find_package(PkgConfig)
find_library(m REQUIRED)

pkg_check_modules(PC_LIBPSPPROXY REQUIRED IMPORTED_TARGET libpspproxy)

add_executable(PSPEmu
                      psp-emu.c
                      psp-core.c
                      psp-disasm.c
                      psp-svc.c
                      psp-flash.c
                      psp-mmio-dev.c
                      psp-smn-dev.c
                      psp-dev-ccp-v5.c
                      psp-dev-unknown-0x03010000.c)

target_include_directories(PSPEmu PUBLIC
                           "${PROJECT_SOURCE_DIR}/include"
                           "${PROJECT_SOURCE_DIR}/psp-includes"
                           "${PROJECT_SOURCE_DIR}/unicorn/include"
                           "${PROJECT_SOURCE_DIR}/capstone/include"
                           "${LIBPSPPROXY_INCLUDE_DIRS}"
                           )

target_link_libraries(PSPEmu PkgConfig::PC_LIBPSPPROXY)
target_link_libraries(PSPEmu ${CMAKE_SOURCE_DIR}/unicorn/libunicorn.a)
target_link_libraries(PSPEmu ${CMAKE_SOURCE_DIR}/capstone/libcapstone.a)
target_link_libraries(PSPEmu m)
target_link_libraries(PSPEmu ${CMAKE_THREAD_LIBS_INIT})
