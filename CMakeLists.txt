cmake_minimum_required(VERSION 3.20)
project(jose2cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(JOSE_BUILD_TESTS "Build tests" ON)
option(JOSE_BUILD_BENCH "Build benchmarks" OFF)
option(JOSE_BUILD_CLI "Build CLI tool" OFF)
option(JOSE_FUZZ "Build fuzz targets (requires libFuzzer)" OFF)
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

# Version header: project(VERSION) above is the single source of truth.
# (Keep vcpkg.json's "version" field in sync when tagging a release.)
configure_file(
    include/jose/version.hpp.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/jose/version.hpp
    @ONLY
)

add_library(jose
    src/base64url.cpp
    src/algorithm.cpp
    src/secure_bytes.cpp
    src/jwk.cpp
    src/header.cpp
    src/jws.cpp
    src/jwe.cpp
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
)

target_include_directories(jose
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Only libcrypto is used (no TLS). zlib is an implementation detail.
target_link_libraries(jose
    PUBLIC
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
    PRIVATE
        ZLIB::ZLIB
)

if(_jose_use_std_expected)
    target_compile_features(jose PUBLIC cxx_std_23)
    target_compile_definitions(jose PUBLIC nsel_CONFIG_SELECT_EXPECTED=nsel_EXPECTED_STD)
else()
    target_compile_features(jose PUBLIC cxx_std_20)
    target_compile_definitions(jose PUBLIC nsel_CONFIG_SELECT_EXPECTED=nsel_EXPECTED_NONSTD)
endif()

if(JOSE_BUILD_TESTS)
    enable_testing()
    find_package(Catch2 3 REQUIRED)
    add_subdirectory(tests)
endif()

if(JOSE_FUZZ)
    add_subdirectory(fuzz)
endif()

# Install
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS jose EXPORT joseTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/jose DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    PATTERN "*.in" EXCLUDE
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/jose/version.hpp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/jose
)
install(EXPORT joseTargets
    FILE joseTargets.cmake
    NAMESPACE jose::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/jose
)

# Config file pulls in OpenSSL/nlohmann_json/ZLIB via find_dependency so that
# find_package(jose) works on a clean machine.
configure_package_config_file(
    cmake/joseConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/joseConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/jose
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/joseConfigVersion.cmake
    # Pre-1.0, minor bumps are breaking (SemVer), so 0.x and 0.y must not
    # satisfy each other. Switch to SameMajorVersion at 1.0.
    COMPATIBILITY SameMinorVersion
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/joseConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/joseConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/jose
)
