cmake_minimum_required(VERSION 3.2.0)
project(zprd)

set(INSTALL_BIN_DIR bin CACHE PATH "Installation directory for binaries")
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")

find_package(Threads REQUIRED)

include_directories(3rdparty/ThreadPool include)

add_executable(zprd src/cksum.c src/crw.c src/main.cxx src/ping_cache.cxx src/recentpkts.cxx src/remote_peer.cxx src/resolve.cxx src/zprn.cxx src/zsig.c)
target_link_libraries(zprd Threads::Threads)
install(TARGETS zprd DESTINATION "${INSTALL_BIN_DIR}")
