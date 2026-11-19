# jose-cli against go-jose's jose-util: each signs and encrypts, the other
# verifies and decrypts, with keys from both tools' generate-key.
#
#   cmake -DJOSE_CLI=... -DJOSE_UTIL=... -DWORK=... -P cli_interop.cmake

foreach(var JOSE_CLI JOSE_UTIL WORK)
    if(NOT DEFINED ${var})
        message(FATAL_ERROR "${var} is not set")
    endif()
endforeach()

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/cli" "${WORK}/util")
set(message "Lorem ipsum dolor sit amet\n")
file(WRITE "${WORK}/message.txt" "${message}")

# run(<input file> <output file> <command...>): fails the case on a non-zero exit.
function(run input output)
    execute_process(COMMAND ${ARGN}
        INPUT_FILE "${input}" OUTPUT_FILE "${output}" ERROR_VARIABLE err RESULT_VARIABLE rc
        WORKING_DIRECTORY "${WORK}")
    if(NOT rc EQUAL 0)
        string(REPLACE ";" " " cmd "${ARGN}")
        message(SEND_ERROR "failed (${rc}): ${cmd}\n${err}")
    endif()
endfunction()

function(expect_message file what)
    file(READ "${file}" got)
    if(NOT got STREQUAL message)
        message(SEND_ERROR "${what}: got '${got}'")
    else()
        message(STATUS "ok: ${what}")
    endif()
endfunction()

# Keys: jose-cli writes jwk-USE-KID-{priv,pub}.json; jose-util writes the
# same names in its working directory.
function(cli_key use alg kid)
    run("${WORK}/message.txt" "${WORK}/null" "${JOSE_CLI}" generate-key --use ${use} --alg ${alg} --kid ${kid}
        --dir "${WORK}/cli")
endfunction()
function(util_key use alg kid)
    execute_process(COMMAND "${JOSE_UTIL}" generate-key --use ${use} --alg ${alg} --kid ${kid}
        WORKING_DIRECTORY "${WORK}/util" RESULT_VARIABLE rc ERROR_VARIABLE err)
    if(NOT rc EQUAL 0)
        message(SEND_ERROR "jose-util generate-key ${alg}: ${err}")
    endif()
endfunction()

set(signing ES256 ES384 ES512 RS256 PS256 EdDSA)
set(encrypting "RSA-OAEP|A128GCM" "RSA-OAEP-256|A256CBC-HS512" "ECDH-ES|A256GCM" "ECDH-ES+A128KW|A128GCM"
               "ECDH-ES+A256KW|A192CBC-HS384")

foreach(alg IN LISTS signing)
    cli_key(sig ${alg} cli-${alg})
    util_key(sig ${alg} util-${alg})
endforeach()
foreach(pair IN LISTS encrypting)
    string(REPLACE "|" ";" parts "${pair}")
    list(GET parts 0 alg)
    string(REPLACE "+" "_" id "${alg}")
    cli_key(enc ${alg} cli-${id})
    util_key(enc ${alg} util-${id})
endforeach()

foreach(alg IN LISTS signing)
    foreach(owner cli util)
        set(priv "${WORK}/${owner}/jwk-sig-${owner}-${alg}-priv.json")
        set(pub "${WORK}/${owner}/jwk-sig-${owner}-${alg}-pub.json")
        run("${WORK}/message.txt" "${WORK}/jws-cli" "${JOSE_CLI}" sign --alg ${alg} --key "${priv}")
        run("${WORK}/jws-cli" "${WORK}/out" "${JOSE_UTIL}" verify --key "${pub}")
        expect_message("${WORK}/out" "jose-cli sign ${alg} (${owner} key) -> jose-util verify")
        run("${WORK}/message.txt" "${WORK}/jws-util" "${JOSE_UTIL}" sign --alg ${alg} --key "${priv}")
        run("${WORK}/jws-util" "${WORK}/out" "${JOSE_CLI}" verify --key "${pub}")
        expect_message("${WORK}/out" "jose-util sign ${alg} (${owner} key) -> jose-cli verify")
        run("${WORK}/message.txt" "${WORK}/jws-full" "${JOSE_UTIL}" sign --full --alg ${alg} --key "${priv}")
        run("${WORK}/jws-full" "${WORK}/out" "${JOSE_CLI}" verify --key "${pub}")
        expect_message("${WORK}/out" "jose-util sign --full ${alg} -> jose-cli verify")
    endforeach()
endforeach()

foreach(pair IN LISTS encrypting)
    string(REPLACE "|" ";" parts "${pair}")
    list(GET parts 0 alg)
    list(GET parts 1 enc)
    string(REPLACE "+" "_" id "${alg}")
    foreach(owner cli util)
        set(priv "${WORK}/${owner}/jwk-enc-${owner}-${id}-priv.json")
        set(pub "${WORK}/${owner}/jwk-enc-${owner}-${id}-pub.json")
        run("${WORK}/message.txt" "${WORK}/jwe-cli" "${JOSE_CLI}" encrypt --alg ${alg} --enc ${enc} --key "${pub}")
        run("${WORK}/jwe-cli" "${WORK}/out" "${JOSE_UTIL}" decrypt --key "${priv}")
        expect_message("${WORK}/out" "jose-cli encrypt ${alg} ${enc} (${owner} key) -> jose-util decrypt")
        run("${WORK}/message.txt" "${WORK}/jwe-util" "${JOSE_UTIL}" encrypt --alg ${alg} --enc ${enc} --key "${pub}")
        run("${WORK}/jwe-util" "${WORK}/out" "${JOSE_CLI}" decrypt --key "${priv}")
        expect_message("${WORK}/out" "jose-util encrypt ${alg} ${enc} (${owner} key) -> jose-cli decrypt")
        run("${WORK}/message.txt" "${WORK}/jwe-full" "${JOSE_CLI}" encrypt --full --zip --alg ${alg} --enc ${enc}
            --key "${pub}")
        run("${WORK}/jwe-full" "${WORK}/out" "${JOSE_UTIL}" decrypt --key "${priv}")
        expect_message("${WORK}/out" "jose-cli encrypt --full --zip ${alg} -> jose-util decrypt")
    endforeach()
endforeach()

# expand gives the same JSON for a JWS (both write the members in the same order).
run("${WORK}/message.txt" "${WORK}/jws" "${JOSE_CLI}" sign --alg ES256 --key "${WORK}/cli/jwk-sig-cli-ES256-priv.json")
run("${WORK}/jws" "${WORK}/expand-cli" "${JOSE_CLI}" expand --format JWS)
run("${WORK}/jws" "${WORK}/expand-util" "${JOSE_UTIL}" expand --format JWS)
file(READ "${WORK}/expand-cli" a)
file(READ "${WORK}/expand-util" b)
if(NOT a STREQUAL b)
    message(SEND_ERROR "expand differs:\njose-cli:  ${a}\njose-util: ${b}")
else()
    message(STATUS "ok: expand --format JWS matches")
endif()
