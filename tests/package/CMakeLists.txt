# A downstream project, built by CI against an installed jose2cpp
# (find_package) and against the source tree (add_subdirectory, as
# FetchContent does). See .github/workflows/ci.yml, job "package".
cmake_minimum_required(VERSION 3.21)
project(jose2cpp_consumer LANGUAGES CXX)

set(JOSE2CPP_SOURCE_DIR "" CACHE PATH "Use this jose2cpp source tree instead of an installed package")
if(JOSE2CPP_SOURCE_DIR)
    add_subdirectory(${JOSE2CPP_SOURCE_DIR} jose2cpp EXCLUDE_FROM_ALL)
else()
    find_package(jose2cpp 0.1 REQUIRED)
endif()

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE jose2cpp::jose2cpp)
# The namespace-style alias names the same library.
add_executable(consumer_alias main.cpp)
target_link_libraries(consumer_alias PRIVATE jose::jose)

enable_testing()
add_test(NAME consumer COMMAND consumer)
add_test(NAME consumer_alias COMMAND consumer_alias)
