# Runs CMD with ARGS (a ;-list) and fails unless it exits with EXPECT.
#   cmake -DCMD=... -DARGS=... -DEXPECT=2 -P check_exit.cmake
execute_process(COMMAND "${CMD}" ${ARGS} RESULT_VARIABLE rc OUTPUT_QUIET ERROR_QUIET)
if(NOT rc STREQUAL "${EXPECT}")
    message(FATAL_ERROR "${CMD} ${ARGS}: exit status ${rc}, expected ${EXPECT}")
endif()
