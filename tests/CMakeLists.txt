add_executable(jose_tests
    test_base64url.cpp
    test_algorithms.cpp
    test_signing.cpp
    test_encryption.cpp
)

target_link_libraries(jose_tests PRIVATE jose Catch2::Catch2WithMain)

include(CTest)
include(Catch)
catch_discover_tests(jose_tests)
