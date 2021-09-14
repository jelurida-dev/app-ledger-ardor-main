cmake_minimum_required(VERSION 3.10)
project(ardor_unit_tests C)

include(CTest)
enable_testing()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -pedantic -g -O0 --coverage")

add_compile_definitions(TEST)

include_directories(include/ ../src)

add_library(ardor
    ../src/reedSolomon.c
    ../src/reedSolomon.h
)

add_executable(test_reedSolomon src/test_reedSolomon.c)

target_link_libraries(test_reedSolomon PUBLIC ardor cmocka)

add_test(test_reedSolomon test_reedSolomon)
