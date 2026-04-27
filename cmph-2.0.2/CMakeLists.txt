cmake_minimum_required(VERSION 3.13)

project(cmph)

add_compile_options(-Wall -Wextra -Werror -Wpedantic -std=gnu99)
add_link_options()

if(CMAKE_BUILD_TYPE MATCHES "Debug_ASan")
    add_compile_options(-Og -g -fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-g -fsanitize=address)
endif()

if(CMAKE_BUILD_TYPE MATCHES "Debug_MSan")
    add_compile_options(-Og -g -fsanitize=memory -fno-omit-frame-pointer)
    add_link_options(-g -fsanitize=memory)
endif()

file(GLOB SRC_LIB "src/*.c")
add_library(${PROJECT_NAME} STATIC ${SRC_LIB})

find_program(CLANGFORMAT clang-format)
if(CLANGFORMAT)
    add_custom_command(
        TARGET ${PROJECT_NAME}
        PRE_BUILD
        COMMAND
            clang-format -i ${CMAKE_CURRENT_SOURCE_DIR}/src/*
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/*
            ${CMAKE_CURRENT_SOURCE_DIR}/examples/*)
endif()

project(cmph_benchmark_test)
add_executable(${PROJECT_NAME} "tests/cmph_benchmark_test.c")
target_include_directories(${PROJECT_NAME} PRIVATE src)
target_link_libraries(${PROJECT_NAME} cmph m)

project(compressed_rank_tests)
add_executable(${PROJECT_NAME} "tests/compressed_rank_tests.c")
target_include_directories(${PROJECT_NAME} PRIVATE src)
target_link_libraries(${PROJECT_NAME} cmph m)

project(compressed_seq_tests)
add_executable(${PROJECT_NAME} "tests/compressed_seq_tests.c")
target_include_directories(${PROJECT_NAME} PRIVATE src)
target_link_libraries(${PROJECT_NAME} cmph m)

project(graph_tests)
add_executable(${PROJECT_NAME} "tests/graph_tests.c")
target_include_directories(${PROJECT_NAME} PRIVATE src)
target_link_libraries(${PROJECT_NAME} cmph m)

project(mphf_tests)
add_executable(${PROJECT_NAME} "tests/mphf_tests.c")
target_include_directories(${PROJECT_NAME} PRIVATE src)
target_link_libraries(${PROJECT_NAME} cmph m)

project(packed_mphf_tests)
add_executable(${PROJECT_NAME} "tests/packed_mphf_tests.c")
target_include_directories(${PROJECT_NAME} PRIVATE src)
target_link_libraries(${PROJECT_NAME} cmph m)

project(select_tests)
add_executable(${PROJECT_NAME} "tests/select_tests.c")
target_include_directories(${PROJECT_NAME} PRIVATE src)
target_link_libraries(${PROJECT_NAME} cmph m)

project(file_adapter_ex2)
add_executable(${PROJECT_NAME} "examples/file_adapter_ex2.c")
target_include_directories(${PROJECT_NAME} PRIVATE src)
target_link_libraries(${PROJECT_NAME} cmph m)

project(small_set_ex4)
add_executable(${PROJECT_NAME} "examples/small_set_ex4.c")
target_include_directories(${PROJECT_NAME} PRIVATE src)
target_link_libraries(${PROJECT_NAME} cmph m)

project(struct_vector_adapter_ex3)
add_executable(${PROJECT_NAME} "examples/struct_vector_adapter_ex3.c")
target_include_directories(${PROJECT_NAME} PRIVATE src)
target_link_libraries(${PROJECT_NAME} cmph m)

project(vector_adapter_ex1)
add_executable(${PROJECT_NAME} "examples/vector_adapter_ex1.c")
target_include_directories(${PROJECT_NAME} PRIVATE src)
target_link_libraries(${PROJECT_NAME} cmph m)
