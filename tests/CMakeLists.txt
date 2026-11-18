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
    test_task.cpp
    test_async.cpp
    test_interop.cpp
    test_jwt.cpp
    test_jwt_claims.cpp
    test_jwt_validate.cpp
    test_jwks_fetcher.cpp
    test_cli.cpp
    test_limits.cpp
    ${PROJECT_SOURCE_DIR}/tools/cli.cpp
    test_vectors.cpp
    support/test_support.cpp
)

target_include_directories(jose_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/tools)
target_compile_definitions(jose_tests PRIVATE
    JOSE_TEST_VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/vectors"
)

target_link_libraries(jose_tests PRIVATE jose Catch2::Catch2WithMain)

include(CTest)
include(Catch)
catch_discover_tests(jose_tests)

# The jose-cli binary itself (its commands are tested in-process by test_cli.cpp).
if(JOSE_BUILD_CLI)
    add_test(NAME cli.help COMMAND jose_cli --help)
    add_test(NAME cli.usage_error
             COMMAND ${CMAKE_COMMAND} -DCMD=$<TARGET_FILE:jose_cli> -DARGS=frobnicate -DEXPECT=2
                     -P ${CMAKE_CURRENT_SOURCE_DIR}/check_exit.cmake)
endif()

# --- go-jose interoperability (PLAN.md Phase 2 item 11) -------------------
#
# test_interop.cpp always checks the checked-in vectors in vectors/interop/.
# jose_interop_gen writes jose2cpp-produced vectors for go-jose to verify.
add_executable(jose_interop_gen interop/gen_jose2cpp.cpp)
target_link_libraries(jose_interop_gen PRIVATE jose)

if(JOSE_INTEROP_GO)
    find_program(GO_EXECUTABLE go REQUIRED)
    set(_go_dir ${CMAKE_CURRENT_SOURCE_DIR}/interop/go)
    set(_fresh ${CMAKE_CURRENT_BINARY_DIR}/interop)
    file(MAKE_DIRECTORY ${_fresh})

    # Fresh vectors in both directions, then each side checks the other's.
    add_test(NAME interop.jose2cpp_generates
             COMMAND jose_interop_gen ${_fresh}/jose2cpp.json)
    set_tests_properties(interop.jose2cpp_generates PROPERTIES FIXTURES_SETUP interop_cpp)
    add_test(NAME interop.go_jose_verifies_jose2cpp
             COMMAND ${GO_EXECUTABLE} run . verify ${_fresh}/jose2cpp.json
             WORKING_DIRECTORY ${_go_dir})
    set_tests_properties(interop.go_jose_verifies_jose2cpp PROPERTIES
        FIXTURES_REQUIRED interop_cpp ENVIRONMENT "GOFLAGS=-mod=readonly")

    add_test(NAME interop.go_jose_generates
             COMMAND ${GO_EXECUTABLE} run . generate ${_fresh}/gojose.json
             WORKING_DIRECTORY ${_go_dir})
    set_tests_properties(interop.go_jose_generates PROPERTIES
        FIXTURES_SETUP interop_go ENVIRONMENT "GOFLAGS=-mod=readonly")
    add_test(NAME interop.jose2cpp_verifies_go_jose
             COMMAND jose_tests "[interop]")
    set_tests_properties(interop.jose2cpp_verifies_go_jose PROPERTIES
        FIXTURES_REQUIRED interop_go ENVIRONMENT "JOSE_INTEROP_GOJOSE=${_fresh}/gojose.json")

    # The checked-in jose2cpp vectors must stay readable by go-jose.
    add_test(NAME interop.go_jose_verifies_checked_in
             COMMAND ${GO_EXECUTABLE} run . verify ${CMAKE_CURRENT_SOURCE_DIR}/vectors/interop/jose2cpp.json
             WORKING_DIRECTORY ${_go_dir})
    set_tests_properties(interop.go_jose_verifies_checked_in PROPERTIES ENVIRONMENT "GOFLAGS=-mod=readonly")

    # jose-cli against go-jose's own jose-util, built from the pinned module.
    if(JOSE_BUILD_CLI)
        add_test(NAME interop.build_jose_util
                 COMMAND ${GO_EXECUTABLE} build -o ${_fresh}/jose-util${CMAKE_EXECUTABLE_SUFFIX}
                         github.com/go-jose/go-jose/v4/jose-util
                 WORKING_DIRECTORY ${_go_dir})
        set_tests_properties(interop.build_jose_util PROPERTIES
            FIXTURES_SETUP jose_util ENVIRONMENT "GOFLAGS=-mod=readonly")
        add_test(NAME interop.cli_vs_jose_util
                 COMMAND ${CMAKE_COMMAND} -DJOSE_CLI=$<TARGET_FILE:jose_cli>
                         -DJOSE_UTIL=${_fresh}/jose-util${CMAKE_EXECUTABLE_SUFFIX} -DWORK=${_fresh}/cli
                         -P ${CMAKE_CURRENT_SOURCE_DIR}/interop/cli_interop.cmake)
        set_tests_properties(interop.cli_vs_jose_util PROPERTIES FIXTURES_REQUIRED jose_util)
    endif()

    # `cmake --build <dir> --target interop_vectors` refreshes the checked-in files.
    add_custom_target(interop_vectors
        COMMAND jose_interop_gen ${CMAKE_CURRENT_SOURCE_DIR}/vectors/interop/jose2cpp.json
        COMMAND ${GO_EXECUTABLE} run . generate ${CMAKE_CURRENT_SOURCE_DIR}/vectors/interop/gojose.json
        COMMAND ${GO_EXECUTABLE} run . verify ${CMAKE_CURRENT_SOURCE_DIR}/vectors/interop/jose2cpp.json
        WORKING_DIRECTORY ${_go_dir}
        COMMENT "Regenerating go-jose interop vectors"
        VERBATIM)
endif()
