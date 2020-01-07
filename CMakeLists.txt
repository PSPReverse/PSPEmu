cmake_minimum_required(VERSION 3.9)

project(PSPEmu VERSION 0.0.0 DESCRIPTION "PSP emulator")

find_package(PkgConfig)
pkg_check_modules(PC_LIBPSPPROXY libpspproxy)

add_executable(PSPEmu psp-emu.c psp-core.c psp-svc.c)

target_include_directories(PSPEmu PUBLIC
                           "${PROJECT_SOURCE_DIR}/include"
                           "${PROJECT_SOURCE_DIR}/psp-include"
                           "${LIBPSPPROXY_INCLUDE_DIR}"
                           )

target_link_libraries(PSPEmu ${LIBPSPPROXY_LIBRARIES})

