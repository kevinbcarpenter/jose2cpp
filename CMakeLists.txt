cmake_minimum_required(VERSION 3.21)
project(jose2cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(PROJECT_IS_TOP_LEVEL)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()

# Pulled into another build (add_subdirectory, FetchContent), jose2cpp builds
# only the library: no tests, and no install rules unless asked for.
option(JOSE_BUILD_TESTS "Build tests" ${PROJECT_IS_TOP_LEVEL})
option(JOSE_INSTALL "Generate install rules (the library, headers, CMake package and pkg-config file)" ${PROJECT_IS_TOP_LEVEL})
option(JOSE_BUILD_BENCH "Build benchmarks" OFF)
option(JOSE_BUILD_CLI "Build CLI tool" OFF)
option(JOSE_FUZZ "Build fuzz targets (requires libFuzzer)" OFF)
option(JOSE_BUILD_DOCS "Add a `jose_docs` target that builds the API reference with Doxygen" OFF)
option(JOSE_DOCS_WARN_AS_ERROR "Fail the `jose_docs` target on any Doxygen warning" OFF)
option(JOSE_INTEROP_GO "Add live go-jose interop tests to ctest (requires Go and network access to fetch go-jose)" OFF)
set(JOSE_USE_STD_EXPECTED AUTO CACHE STRING
    "Use std::expected (requires C++23): AUTO, ON, or OFF (OFF = vendored expected-lite on C++20)")
set_property(CACHE JOSE_USE_STD_EXPECTED PROPERTY STRINGS AUTO ON OFF)

# jose::expected is std::expected under C++23, expected-lite under C++20.
# Resolve the choice once at configure time and export it as a PUBLIC
# compile definition so library and consumers always agree on the type.
if(JOSE_USE_STD_EXPECTED STREQUAL "AUTO")
    include(CheckCXXSourceCompiles)
    set(_saved_std "${CMAKE_CXX_STANDARD}")
    set(CMAKE_CXX_STANDARD 23)
    check_cxx_source_compiles("
        #include <expected>
        int main() { std::expected<int, int> e{1}; return *e - 1; }
    " JOSE_HAS_STD_EXPECTED)
    set(CMAKE_CXX_STANDARD "${_saved_std}")
    set(_jose_use_std_expected "${JOSE_HAS_STD_EXPECTED}")
elseif(JOSE_USE_STD_EXPECTED)
    set(_jose_use_std_expected ON)
else()
    set(_jose_use_std_expected OFF)
endif()

if(_jose_use_std_expected)
    set(CMAKE_CXX_STANDARD 23)
    message(STATUS "jose::expected: std::expected (C++23)")
else()
    set(CMAKE_CXX_STANDARD 20)
    message(STATUS "jose::expected: vendored expected-lite (C++20)")
endif()

find_package(OpenSSL 3.0 REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(ZLIB REQUIRED) # raw DEFLATE for JWE "zip":"DEF" (RFC 7516 §4.1.3)

# Fuzzing (PLAN.md §Fuzz Testing). Everything, the library included, is
# built with JOSE_FUZZ_SANITIZERS; with a compiler that has libFuzzer the
# library is also instrumented for coverage and the targets are fuzzers,
# otherwise they replay their corpus (fuzz/replay_main.cpp).
set(JOSE_FUZZ_SANITIZERS "address,undefined" CACHE STRING "Sanitizers for the fuzz build (-fsanitize=...); empty for none")
if(JOSE_FUZZ)
    if(MSVC)
        message(FATAL_ERROR "JOSE_FUZZ needs clang or GCC (the fuzz flags are -fsanitize=...); "
                            "build the fuzz targets with clang on Linux or macOS")
    endif()
    include(CheckCXXSourceCompiles)
    set(CMAKE_REQUIRED_LINK_OPTIONS -fsanitize=fuzzer)
    set(CMAKE_REQUIRED_FLAGS -fsanitize=fuzzer)
    check_cxx_source_compiles([[
        #include <cstddef>
        #include <cstdint>
        extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t*, std::size_t) { return 0; }
    ]] JOSE_HAS_LIBFUZZER)
    unset(CMAKE_REQUIRED_LINK_OPTIONS)
    unset(CMAKE_REQUIRED_FLAGS)
    if(JOSE_HAS_LIBFUZZER)
        # Coverage instrumentation goes on the library and the fuzz targets
        # (below and in fuzz/); anything else linking the library gets the
        # coverage runtime through its public link option.
        message(STATUS "Fuzz targets: libFuzzer")
    else()
        message(STATUS "Fuzz targets: corpus replayers (this compiler has no libFuzzer)")
    endif()
    if(JOSE_FUZZ_SANITIZERS)
        add_compile_options(-fsanitize=${JOSE_FUZZ_SANITIZERS} -fno-omit-frame-pointer -fno-sanitize-recover=all)
        add_link_options(-fsanitize=${JOSE_FUZZ_SANITIZERS})
    endif()
    # Keep assertions in any build type: expected-lite checks dereferencing
    # an error with assert(), and libstdc++'s checks catch bad optional and
    # vector access.
    add_compile_options(-UNDEBUG -D_GLIBCXX_ASSERTIONS)
endif()

# Version header: project(VERSION) above is the single source of truth.
# (Keep vcpkg.json's "version" field in sync when tagging a release.)
configure_file(
    include/jose/version.hpp.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/jose/version.hpp
    @ONLY
)

add_library(jose2cpp
    src/base64url.cpp
    src/algorithm.cpp
    src/secure_bytes.cpp
    src/jwk.cpp
    src/header.cpp
    src/jws.cpp
    src/jwe.cpp
    src/jwt.cpp
    src/jwt_claims.cpp
    src/internal/deflate.cpp
    src/internal/codec.cpp
    src/crypto/hmac.cpp
    src/crypto/rsa.cpp
    src/crypto/ec.cpp
    src/crypto/eddsa.cpp
    src/crypto/signing.cpp
    src/crypto/keygen.cpp
    src/crypto/aes_kw.cpp
    src/crypto/aes_gcm_kw.cpp
    src/crypto/aes_cbc_hmac.cpp
    src/crypto/aes_gcm.cpp
    src/crypto/encryption.cpp
    src/crypto/ecdh.cpp
    src/crypto/pbes2.cpp
    # Opt-in by include (jose/optional/jwks_fetcher.hpp); no extra dependencies.
    src/optional/jwks_fetcher.cpp
)
# The installed package exports jose2cpp::jose2cpp (and jose::jose, see
# cmake/jose2cppConfig.cmake.in); the same names work from a source tree.
add_library(jose2cpp::jose2cpp ALIAS jose2cpp)
add_library(jose::jose ALIAS jose2cpp)

# Pre-1.0 every minor release may break the ABI (as with
# SameMinorVersion below), so the soname carries major.minor:
# libjose2cpp.so.0.1 on Linux. Not "jose": that name belongs to
# latchset's C library (libjose, jose.pc) in Debian and Ubuntu.
set_target_properties(jose2cpp PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
)

target_include_directories(jose2cpp
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Only libcrypto is used (no TLS). zlib is an implementation detail.
target_link_libraries(jose2cpp
    PUBLIC
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
    PRIVATE
        ZLIB::ZLIB
)

if(JOSE_FUZZ AND JOSE_HAS_LIBFUZZER)
    # The instrumented library needs the coverage runtime in whatever links
    # it (the tests and the CLI too), so the link option is public.
    target_compile_options(jose2cpp PRIVATE -fsanitize=fuzzer-no-link)
    target_link_options(jose2cpp PUBLIC -fsanitize=fuzzer-no-link)
endif()

if(_jose_use_std_expected)
    target_compile_features(jose2cpp PUBLIC cxx_std_23)
    target_compile_definitions(jose2cpp PUBLIC nsel_CONFIG_SELECT_EXPECTED=nsel_EXPECTED_STD)
else()
    target_compile_features(jose2cpp PUBLIC cxx_std_20)
    target_compile_definitions(jose2cpp PUBLIC nsel_CONFIG_SELECT_EXPECTED=nsel_EXPECTED_NONSTD)
endif()

# API reference: docs/Doxyfile with the output directory and version
# filled in. Doxygen runs from the source directory, where the Doxyfile's
# relative paths point.
if(JOSE_BUILD_DOCS)
    find_package(Doxygen REQUIRED)
    set(JOSE_DOCS_DIR ${CMAKE_CURRENT_BINARY_DIR}/docs)
    if(JOSE_DOCS_WARN_AS_ERROR)
        set(_jose_docs_warn FAIL_ON_WARNINGS)
    else()
        set(_jose_docs_warn NO)
    endif()
    file(GENERATE OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.jose CONTENT
"@INCLUDE = \"${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile\"
OUTPUT_DIRECTORY = \"${JOSE_DOCS_DIR}\"
PROJECT_NUMBER = ${PROJECT_VERSION}
WARN_AS_ERROR = ${_jose_docs_warn}
")
    add_custom_target(jose_docs
        COMMAND Doxygen::doxygen ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.jose
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Building the API reference in ${JOSE_DOCS_DIR}/html"
        VERBATIM
    )
endif()

if(JOSE_BUILD_TESTS)
    enable_testing()
    find_package(Catch2 3 REQUIRED)
    add_subdirectory(tests)
endif()

if(JOSE_FUZZ)
    enable_testing()
    add_subdirectory(fuzz)
endif()

if(JOSE_BUILD_BENCH)
    add_subdirectory(benchmarks)
endif()

# jose-cli (PLAN.md Phase 3 item 8). The commands are in tools/cli.cpp so the
# tests can run them in-process.
if(JOSE_BUILD_CLI)
    add_executable(jose_cli tools/jose_cli.cpp tools/cli.cpp)
    set_target_properties(jose_cli PROPERTIES OUTPUT_NAME jose-cli)
    target_link_libraries(jose_cli PRIVATE jose2cpp)
endif()

# Install: find_package(jose2cpp) and pkg-config jose2cpp. Package, library
# and pkg-config names are all jose2cpp; the headers stay under <jose/...>
# and the namespace is jose.
if(JOSE_INSTALL)
    include(GNUInstallDirs)
    include(CMakePackageConfigHelpers)
    set(_jose_cmake_dir ${CMAKE_INSTALL_LIBDIR}/cmake/jose2cpp)

    if(JOSE_BUILD_CLI)
        install(TARGETS jose_cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    endif()

    install(TARGETS jose2cpp EXPORT jose2cppTargets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
    install(DIRECTORY include/jose DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        PATTERN "*.in" EXCLUDE
    )
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/jose/version.hpp
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/jose
    )
    install(EXPORT jose2cppTargets
        FILE jose2cppTargets.cmake
        NAMESPACE jose2cpp::
        DESTINATION ${_jose_cmake_dir}
    )

    # The config file pulls in OpenSSL, nlohmann_json and ZLIB with
    # find_dependency, so find_package(jose2cpp) works on a clean machine.
    configure_package_config_file(
        cmake/jose2cppConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/jose2cppConfig.cmake
        INSTALL_DESTINATION ${_jose_cmake_dir}
    )
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/jose2cppConfigVersion.cmake
        # Pre-1.0, minor bumps are breaking (SemVer), so 0.x and 0.y must not
        # satisfy each other. Switch to SameMajorVersion at 1.0, along with
        # the SOVERSION above.
        COMPATIBILITY SameMinorVersion
    )
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/jose2cppConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/jose2cppConfigVersion.cmake
        DESTINATION ${_jose_cmake_dir}
    )

    # pkg-config. With the usual relative install dirs the prefix is found
    # from the .pc file's own location, so `cmake --install --prefix`
    # anywhere gives a working file. An absolute libdir or includedir (Nix,
    # some distro builds) is written as it is, and that file isn't
    # relocatable.
    if(IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}" OR IS_ABSOLUTE "${CMAKE_INSTALL_INCLUDEDIR}")
        set(JOSE_PC_PREFIX "${CMAKE_INSTALL_PREFIX}")
        set(JOSE_PC_INCLUDEDIR "${CMAKE_INSTALL_FULL_INCLUDEDIR}")
        set(JOSE_PC_LIBDIR "${CMAKE_INSTALL_FULL_LIBDIR}")
    else()
        file(RELATIVE_PATH _jose_pc_to_prefix "/${CMAKE_INSTALL_LIBDIR}/pkgconfig" "/")
        string(REGEX REPLACE "/$" "" _jose_pc_to_prefix "${_jose_pc_to_prefix}")
        set(JOSE_PC_PREFIX "\${pcfiledir}/${_jose_pc_to_prefix}")
        set(JOSE_PC_INCLUDEDIR "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
        set(JOSE_PC_LIBDIR "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
    endif()
    if(_jose_use_std_expected)
        set(JOSE_PC_EXPECTED nsel_EXPECTED_STD)
        set(JOSE_PC_STD 23)
    else()
        set(JOSE_PC_EXPECTED nsel_EXPECTED_NONSTD)
        set(JOSE_PC_STD 20)
    endif()
    configure_file(cmake/jose2cpp.pc.in ${CMAKE_CURRENT_BINARY_DIR}/jose2cpp.pc @ONLY)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/jose2cpp.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
    )
endif()
