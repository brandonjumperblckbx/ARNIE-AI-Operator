cmake_minimum_required(VERSION 3.20)
project(arnie-performance VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(nlohmann_json 3.11 QUIET)

add_library(arnie_performance
    src/event_processor.cpp
    src/playbook_analyzer.cpp
)

target_include_directories(arnie_performance PUBLIC include)

if(nlohmann_json_FOUND)
    target_link_libraries(arnie_performance PRIVATE nlohmann_json::nlohmann_json)
endif()

add_executable(arnie_perf_service src/main.cpp)
target_link_libraries(arnie_perf_service PRIVATE arnie_performance)
