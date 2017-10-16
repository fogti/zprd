cmake_minimum_required(VERSION 3.1.0)
project(zprd)

set(INSTALL_BIN_DIR bin CACHE PATH "Installation directory for binaries")
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/src")
add_executable(zprd src/cksum.c src/crw.c src/main.cxx src/recentpkts.cxx src/resolve.cxx src/zsig.c)
install(TARGETS zprd DESTINATION "${INSTALL_BIN_DIR}")
