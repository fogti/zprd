cmake_minimum_required(VERSION 3.1.0)
project(zprd)

set(INSTALL_BIN_DIR bin CACHE PATH "Installation directory for binaries")
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
option(USE_TBB "use the Intel Threading Building Blocks library" ON)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

find_package(Threads REQUIRED)
if(USE_TBB)
  find_package(TBB)
else()
  set(TBB_FOUND OFF)
endif()

configure_file(include/config.h.in "${PROJECT_BINARY_DIR}/config.h")
include_directories($<$<COMPILE_LANGUAGE:CXX>:${PROJECT_SOURCE_DIR}/3rdparty/ThreadPool>
    src include "${PROJECT_BINARY_DIR}")

if(${TBB_FOUND})
  include_directories(${TBB_INCLUDE_DIRS})
  add_definitions(${TBB_DEFINITIONS})
endif()

add_executable(zprd src/main.cxx src/cksum.cxx src/crw.c src/ping_cache.cxx
                    src/remote_peer.cxx src/resolve.cxx src/routes.cxx src/zprn.cxx src/zsig.c)
target_link_libraries(zprd Threads::Threads)

if(${TBB_FOUND})
  target_link_libraries(zprd ${TBB_LIBRARIES})
endif()

function(src_compile_flags flag)
  set_property(SOURCE ${ARGN} APPEND_STRING PROPERTY COMPILE_FLAGS " ${flag}")
endfunction()

# use -fno-rtti on all C++ sources except the ones which use TBB
src_compile_flags("-fno-rtti"
  src/ping_cache.cxx src/remote_peer.cxx src/resolve.cxx src/routes.cxx src/zprn.cxx)

# disable exceptions for files, which only contain 'noexcept' functions
src_compile_flags("-fno-exceptions -fno-unwind-tables"
  src/cksum.cxx src/ping_cache.cxx src/remote_peer.cxx src/resolve.cxx src/zprn.cxx)

install(TARGETS zprd DESTINATION "${INSTALL_BIN_DIR}")
