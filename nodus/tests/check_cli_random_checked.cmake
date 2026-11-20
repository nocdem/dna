# K-02 (governance proposal nonce): nodus-cli must look at the result of every
# nodus_random call. A call used as a bare statement discards the result, so a
# failed draw would leave the proposal nonce unset (and the proposal would go
# out with an indeterminate nonce).
#
# Proves: no line of tools/nodus-cli.c starts (after blanks) with a
#   nodus_random( call, i.e. every call there sits inside a condition or an
#   assignment whose result is used.
# Run as: cmake -DCLI_SOURCE=<path to nodus-cli.c> -P check_cli_random_checked.cmake
# Flags/env: none. Leaves behind: nothing (read only).
# How it can falsely pass: it is a source-shape check, not a run with a
#   failing random source: a call whose result is assigned and then ignored,
#   or a call split over lines with the name not at a line start, is not
#   seen. It covers nodus-cli.c only (the DHT backend/server and the
#   channel-server draws are outside this record). Before the fix the
#   governance-nonce draw is a bare statement and the check fails.

if(NOT CLI_SOURCE)
    message(FATAL_ERROR "CLI_SOURCE not set")
endif()
file(STRINGS "${CLI_SOURCE}" _lines REGEX "^[ \t]*nodus_random\\(")
list(LENGTH _lines _n)
if(_n GREATER 0)
    message(FATAL_ERROR
        "nodus-cli.c discards the result of nodus_random in ${_n} place(s):\n${_lines}")
endif()
message(STATUS "every nodus_random call in nodus-cli.c has its result checked")
