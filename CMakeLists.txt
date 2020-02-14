cmake_minimum_required(VERSION 3.10.2)
project(dlsag)
set(CMAKE_CXX_STANDARD 14)
#add_link_options(-lsodium)
add_executable(dlsag src/main.cpp include/lsag.h src/dlsag.cpp include/dlsag.h include/helper.h src/helper.cpp src/lsag.cpp)
#add this for lib
target_link_libraries(dlsag libsodium.a)

