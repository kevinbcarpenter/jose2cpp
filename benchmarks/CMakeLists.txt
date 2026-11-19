# Benchmarks (PLAN.md Phase 3 item 11, §Benchmarks). benchmarks/compare.py
# runs jose_bench next to the go-jose runner in benchmarks/go.

add_executable(jose_bench bench_main.cpp)
target_link_libraries(jose_bench PRIVATE jose2cpp)
target_compile_definitions(jose_bench PRIVATE JOSE_BENCH_KEYS="${CMAKE_CURRENT_SOURCE_DIR}/keys.json")

get_property(_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
# A warning for a build meant for timing; a test build (CI's, say) only runs
# the smoke tests, so a status line will do there. jose_bench says so too.
if(JOSE_BUILD_TESTS)
    set(_bench_msg STATUS)
else()
    set(_bench_msg WARNING)
endif()
if(NOT _multi_config AND NOT CMAKE_BUILD_TYPE MATCHES "^(Release|RelWithDebInfo|MinSizeRel)$")
    message(${_bench_msg} "JOSE_BUILD_BENCH: CMAKE_BUILD_TYPE is '${CMAKE_BUILD_TYPE}', so the library and "
                    "jose_bench are unoptimized. Use the bench preset or -DCMAKE_BUILD_TYPE=Release for "
                    "numbers worth comparing.")
endif()

# Smoke tests: every case runs once and its round trip is checked, so the
# benchmarks keep building and keep measuring the success path.
if(JOSE_BUILD_TESTS OR JOSE_FUZZ)
    add_test(NAME bench.smoke COMMAND jose_bench --quick)
    if(JOSE_INTEROP_GO)
        find_program(GO_EXECUTABLE go REQUIRED)
        add_test(NAME bench.go_smoke COMMAND ${GO_EXECUTABLE} run . --quick
                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/go)
        set_tests_properties(bench.go_smoke PROPERTIES ENVIRONMENT "GOFLAGS=-mod=readonly")
    endif()
endif()
