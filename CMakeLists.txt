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
                      psp-svc.c
                      psp-flash.c
                      psp-mmio-dev.c
                      psp-dev-ccp-v5.c
                      psp-dev-unknown-0x01005000.c
                      psp-dev-unknown-0x0125a000.c
                      psp-dev-unknown-0x03010000.c
                      psp-dev-unknown-0x03200000.c
                      psp-dev-unknown-0x03210000.c
                      psp-dev-unknown-0x03220000.c
                      psp-dev-unknown-0x03260000.c)

target_include_directories(PSPEmu PUBLIC
                           "${PROJECT_SOURCE_DIR}/include"
                           "${PROJECT_SOURCE_DIR}/psp-includes"
                           "${PROJECT_SOURCE_DIR}/unicorn/include"
                           "${LIBPSPPROXY_INCLUDE_DIRS}"
                           )

target_link_libraries(PSPEmu PkgConfig::PC_LIBPSPPROXY)
target_link_libraries(PSPEmu ${CMAKE_SOURCE_DIR}/unicorn/libunicorn.a)
target_link_libraries(PSPEmu m)
target_link_libraries(PSPEmu ${CMAKE_THREAD_LIBS_INIT})
