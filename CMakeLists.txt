cmake_minimum_required(VERSION 3.1.0)
project(zprd)

set(INSTALL_BIN_DIR bin CACHE PATH "Installation directory for binaries")
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
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
include_directories(3rdparty/ThreadPool include "${PROJECT_BINARY_DIR}")

if(${TBB_FOUND})
  include_directories(${TBB_INCLUDE_DIRS})
  add_definitions(${TBB_DEFINITIONS})
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif()

add_executable(zprd src/main.cxx src/cksum.cxx src/crw.c src/ping_cache.cxx
                    src/remote_peer.cxx src/resolve.cxx src/routes.cxx src/zprn.cxx src/zsig.c)
target_link_libraries(zprd Threads::Threads)

if(${TBB_FOUND})
  target_link_libraries(zprd ${TBB_LIBRARIES})
endif()

install(TARGETS zprd DESTINATION "${INSTALL_BIN_DIR}")
