# Fuzz targets (PLAN.md §Fuzz Testing), built with -DJOSE_FUZZ=ON.
#
# With libFuzzer (clang on Linux, or LLVM's own clang on macOS) each target
# is a fuzzer:
#     ./fuzz_jws -max_total_time=60 <scratch copy of fuzz/corpus/jws>
# Without it (Apple clang, GCC) each one replays the files it's given.
# MSVC isn't supported (the top-level CMakeLists says so).
# Either way ctest replays the checked-in corpus under the sanitizers.

enable_testing()

set(JOSE_FUZZ_TARGETS base64url jwk jws jwe jwt inflate)

foreach(name IN LISTS JOSE_FUZZ_TARGETS)
    add_executable(fuzz_${name} fuzz_${name}.cpp)
    target_link_libraries(fuzz_${name} PRIVATE jose2cpp)
    # fuzz_inflate reaches the internal inflater.
    target_include_directories(fuzz_${name} PRIVATE ${PROJECT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR})
    set(corpus ${CMAKE_CURRENT_SOURCE_DIR}/corpus/${name})
    if(JOSE_HAS_LIBFUZZER)
        target_compile_options(fuzz_${name} PRIVATE -fsanitize=fuzzer)
        target_link_options(fuzz_${name} PRIVATE -fsanitize=fuzzer)
        # -runs=0: run the corpus once, don't fuzz (and don't write to it).
        add_test(NAME fuzz.${name}.corpus COMMAND fuzz_${name} -runs=0 ${corpus})
    else()
        target_sources(fuzz_${name} PRIVATE replay_main.cpp)
        add_test(NAME fuzz.${name}.corpus COMMAND fuzz_${name} ${corpus})
    endif()
    # GCC replay builds without optimization take a minute or two on jwe.
    set_tests_properties(fuzz.${name}.corpus PROPERTIES TIMEOUT 900)
endforeach()
