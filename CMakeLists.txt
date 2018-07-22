cmake_minimum_required(VERSION 3.1.0)
project(zprd)

set(INSTALL_BIN_DIR bin CACHE PATH "Installation directory for binaries")
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
option(USE_TBB "use the Intel Threading Building Blocks library" ON)
option(USE_ABI_32 "build 32bit executable" ON)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

find_package(Threads REQUIRED)
if(USE_TBB)
  find_package(TBB)
else()
  set(TBB_FOUND OFF)
endif()

include(CheckCSourceCompiles)
include(CheckCXXSourceCompiles)
check_c_source_compiles(
  "int main(void) { return __builtin_expect(0, 1); }" HAVE_BUILTIN_EXPECT)

check_c_source_compiles(
  "static int __attribute__((pure)) zs_st_pure_func(const int x) { return 2 * x; }\nint main(void) { return zs_st_pure_func(0); }"
  HAVE_ATTRIB_PURE)

check_cxx_source_compiles(
  "#include <map>\n#include <utility>\nint main(void) { std::map<int, int> m{{1,5}, {2,10} }; auto nh = m.extract(2); nh.key() = 4; m.insert(std::move(nh)); return 0; }"
  HAVE_MAP_EXTRACT)

configure_file(include/config.h.in "${PROJECT_BINARY_DIR}/config.h")
include_directories(src include "${PROJECT_BINARY_DIR}")

if(${TBB_FOUND})
  include_directories(${TBB_INCLUDE_DIRS})
  add_definitions(${TBB_DEFINITIONS})
endif()

if(USE_ABI_32)
  set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -m32")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
endif()

set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -fno-plt -ftree-vectorize -fno-unwind-tables -fno-asynchronous-unwind-tables")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-plt -ftree-vectorize -fno-rtti -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables")

add_executable(zprd src/main.cxx src/cksum.c src/crw.c src/hash.c src/ping_cache.cxx
                    src/remote_peer.cxx src/resolve.cxx src/routes.cxx src/zprn.cxx src/zsig.c)
target_link_libraries(zprd Threads::Threads)

if(${TBB_FOUND})
  target_link_libraries(zprd ${TBB_LIBRARIES})
endif()

function(src_compile_flags flag)
  set_property(SOURCE ${ARGN} APPEND_STRING PROPERTY COMPILE_FLAGS " ${flag}")
endfunction()

# use -fno-rtti on all C++ sources except the ones which use tbb::parallel_sort
src_compile_flags("-frtti" src/main.cxx)

# disable exceptions for files, which only contain 'noexcept' functions
src_compile_flags("-fexceptions -funwind-tables" src/main.cxx src/routes.cxx)

install(TARGETS zprd DESTINATION "${INSTALL_BIN_DIR}")
