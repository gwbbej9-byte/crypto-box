cmake_minimum_required(VERSION 3.20)
project(crypto-box LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(cbox_crypto STATIC src/crypto.cpp src/crypto.hpp)
target_include_directories(cbox_crypto PUBLIC src)
target_link_libraries(cbox_crypto PUBLIC bcrypt)

add_executable(crypto-box WIN32 src/main.cpp)
target_link_libraries(crypto-box PRIVATE cbox_crypto user32 gdi32 comdlg32)

add_executable(cbox_tests tests/cbox_tests.cpp)
target_link_libraries(cbox_tests PRIVATE cbox_crypto)

if (MSVC)
  foreach(tgt IN ITEMS cbox_crypto crypto-box cbox_tests)
    target_compile_options(${tgt} PRIVATE /W4 /permissive- /utf-8)
    target_compile_definitions(${tgt} PRIVATE NOMINMAX UNICODE _UNICODE)
  endforeach()
endif()

enable_testing()
add_test(NAME cbox_tests COMMAND cbox_tests)
