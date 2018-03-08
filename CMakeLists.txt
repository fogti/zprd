cmake_minimum_required(VERSION 3.1.0)
project(zprd)

set(INSTALL_BIN_DIR bin CACHE PATH "Installation directory for binaries")
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")

find_package(Threads REQUIRED)

include_directories(3rdparty/ThreadPool include)

add_executable(zprd src/main.cxx src/crest.c src/crw.c src/ping_cache.cxx src/remote_peer.cxx src/resolve.cxx src/zprn.cxx)
target_link_libraries(zprd Threads::Threads)
install(TARGETS zprd DESTINATION "${INSTALL_BIN_DIR}")
