set(CMAKE_LEGACY_CYGWIN_WIN32 0)

cmake_minimum_required(VERSION 3.13)
project(epk2extract)

if( NOT CMAKE_BUILD_TYPE )
	set(CMAKE_BUILD_TYPE Debug)
endif()

set(CMAKE_CXX_FLAGS_TEST "-Ofast")
set(CMAKE_C_FLAGS_TEST "-Ofast -funroll-loops -fprefetch-loop-arrays -march=native")

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 11)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake-modules/")
find_package(OpenSSL REQUIRED)
find_package(LZO REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
find_library(M_LIB m REQUIRED)

add_subdirectory(src)
