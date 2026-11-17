add_executable(jose_tests
    test_base64url.cpp
    test_algorithms.cpp
    test_signing.cpp
    test_encryption.cpp
    test_secure_bytes.cpp
    test_openssl_errors.cpp
    test_jwk.cpp
    test_header.cpp
    test_jws.cpp
    test_jwe.cpp
    test_opaque.cpp
    test_vectors.cpp
    support/test_support.cpp
)

target_include_directories(jose_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(jose_tests PRIVATE
    JOSE_TEST_VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/vectors"
)

target_link_libraries(jose_tests PRIVATE jose Catch2::Catch2WithMain)

include(CTest)
include(Catch)
catch_discover_tests(jose_tests)
