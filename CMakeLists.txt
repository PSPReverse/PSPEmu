cmake_minimum_required(VERSION 3.9)

project(PSPEmu VERSION 0.0.0 DESCRIPTION "PSP emulator")

set(CMAKE_THREAD_PREFER_PTHREAD On)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DIN_PSP_EMULATOR")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
find_package (Threads)
find_package(PkgConfig)
find_package(ZLIB REQUIRED)
find_library(m REQUIRED)

pkg_check_modules(PC_LIBPSPPROXY REQUIRED IMPORTED_TARGET libpspproxy)
pkg_check_modules(PC_OPENSSL     REQUIRED IMPORTED_TARGET openssl)

add_executable(PSPEmu
                      psp-emu.c
                      psp-core.c
                      psp-ccd.c
                      psp-disasm.c
                      psp-dbg.c
                      psp-svc.c
                      psp-flash.c
                      psp-iom.c
                      psp-trace.c
                      psp-proxy.c
                      psp-dev.c
                      psp-dev-ccp-v5.c
                      psp-dev-timer.c
                      psp-dev-test.c
                      psp-dev-fuse.c
                      psp-dev-flash.c
                      psp-dev-smu.c
                      psp-dev-mp2.c
                      psp-dev-status.c
                      psp-dev-acpi.c
                      psp-dev-x86-uart.c
                      psp-dev-x86-mem.c
                      psp-dev-mmio-unknown.c
                      psp-dev-smn-unknown.c
                      psp-dev-x86-unknown.c)

target_include_directories(PSPEmu PUBLIC
                           "${PROJECT_SOURCE_DIR}/include"
                           "${PROJECT_SOURCE_DIR}/psp-includes"
                           "${PROJECT_SOURCE_DIR}/unicorn/include"
                           "${PROJECT_SOURCE_DIR}/capstone/include"
                           "${PROJECT_SOURCE_DIR}/libgdbstub"
                           "${LIBPSPPROXY_INCLUDE_DIRS}"
                           "${ZLIB_INCLUDE_DIRS}"
                           )

target_link_libraries(PSPEmu PkgConfig::PC_LIBPSPPROXY)
target_link_libraries(PSPEmu PkgConfig::PC_OPENSSL)
target_link_libraries(PSPEmu ${ZLIB_LIBRARIES})
target_link_libraries(PSPEmu ${CMAKE_SOURCE_DIR}/unicorn/libunicorn.a)
target_link_libraries(PSPEmu ${CMAKE_SOURCE_DIR}/capstone/libcapstone.a)
target_link_libraries(PSPEmu ${CMAKE_SOURCE_DIR}/libgdbstub/libgdbstub.a)
target_link_libraries(PSPEmu m)
target_link_libraries(PSPEmu ${CMAKE_THREAD_LIBS_INIT})
