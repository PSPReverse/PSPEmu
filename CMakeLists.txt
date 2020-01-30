cmake_minimum_required(VERSION 3.9)

project(PSPEmu VERSION 0.0.0 DESCRIPTION "PSP emulator")

set(CMAKE_THREAD_PREFER_PTHREAD On)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DIN_PSP_EMULATOR")
find_package (Threads)
find_package(PkgConfig)
find_library(m REQUIRED)

pkg_check_modules(PC_LIBPSPPROXY REQUIRED IMPORTED_TARGET libpspproxy)

add_executable(PSPEmu
                      psp-emu.c
                      psp-core.c
                      psp-disasm.c
                      psp-dbg.c
                      psp-svc.c
                      psp-flash.c
                      psp-iom.c
                      psp-dev.c
                      psp-dev-ccp-v5.c
                      psp-dev-timer.c
                      psp-dev-mmio-unknown.c
                      psp-dev-smn-unknown.c)

target_include_directories(PSPEmu PUBLIC
                           "${PROJECT_SOURCE_DIR}/include"
                           "${PROJECT_SOURCE_DIR}/psp-includes"
                           "${PROJECT_SOURCE_DIR}/unicorn/include"
                           "${PROJECT_SOURCE_DIR}/capstone/include"
                           "${PROJECT_SOURCE_DIR}/libgdbstub"
                           "${LIBPSPPROXY_INCLUDE_DIRS}"
                           )

target_link_libraries(PSPEmu PkgConfig::PC_LIBPSPPROXY)
target_link_libraries(PSPEmu ${CMAKE_SOURCE_DIR}/unicorn/libunicorn.a)
target_link_libraries(PSPEmu ${CMAKE_SOURCE_DIR}/capstone/libcapstone.a)
target_link_libraries(PSPEmu ${CMAKE_SOURCE_DIR}/libgdbstub/libgdbstub.a)
target_link_libraries(PSPEmu m)
target_link_libraries(PSPEmu ${CMAKE_THREAD_LIBS_INIT})
