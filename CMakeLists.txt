cmake_minimum_required(VERSION 3.1.0)
project(zprd)

set(INSTALL_LIB_DIR "lib${LIB_SUFFIX}" CACHE PATH "Installation directory for libraries")
set(INSTALL_INCLUDE_DIR include CACHE PATH "Installation directory for libraries")
set(INSTALL_BIN_DIR bin CACHE PATH "Installation directory for binaries")
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
option(USE_IPV6 "enable outer IPv6 support" ON)
option(USE_IPX  "enable AFa IPX support" OFF)

find_package(Threads REQUIRED)
find_package(LowlevelZS REQUIRED)

include(CheckCSourceCompiles)
include(CheckCXXSourceCompiles)
check_c_source_compiles(
  "int main(void) { return __builtin_expect(0, 1); }" HAVE_BUILTIN_EXPECT)

check_c_source_compiles(
  "static int __attribute__((pure)) zs_st_pure_func(const int x) { return 2 * x; }\nint main(void) { return zs_st_pure_func(0); }"
  HAVE_ATTRIB_PURE)

configure_file(include/config.h.in "${PROJECT_BINARY_DIR}/config.h")
include_directories(libzsneta src include "${PROJECT_BINARY_DIR}")

set(Z_COMMON_C_FLAGS "-fno-plt -ftree-vectorize -fno-unwind-tables -fno-asynchronous-unwind-tables")
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   ${Z_COMMON_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${Z_COMMON_C_FLAGS} -fno-rtti -fno-exceptions")

add_library(zsneta SHARED libzsneta/AFa.cxx libzsneta/iAFa.cxx)
target_link_libraries(zsneta LowlevelZS::lowlevelzs)

if(USE_IPX)
  target_link_libraries(zsneta -lipx)
endif()

install(TARGETS zsneta DESTINATION "${INSTALL_LIB_DIR}")
install(FILES libzsneta/AFa.hpp libzsneta/iAFa.hpp DESTINATION "${INSTALL_INCLUDE_DIR}/libzsneta")

add_executable(zprd src/main.cxx src/cksum.c src/crw.c src/ping_cache.cxx
                    src/remote_peer.cxx src/remote_peer_detail.cxx
                    src/resolve.cxx src/routes.cxx src/sender.cxx src/zprn.cxx)
target_link_libraries(zprd Threads::Threads zsneta)

function(src_compile_flags flag)
  set_property(SOURCE ${ARGN} APPEND_STRING PROPERTY COMPILE_FLAGS " ${flag}")
endfunction()

# disable exceptions for files, which only contain 'noexcept' functions
src_compile_flags("-fexceptions -funwind-tables" src/main.cxx src/routes.cxx)

install(TARGETS zprd DESTINATION "${INSTALL_BIN_DIR}")
