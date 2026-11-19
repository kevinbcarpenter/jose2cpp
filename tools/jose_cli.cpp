// jose-cli: sign, verify, encrypt, decrypt and expand JOSE objects and
// generate keys, from the command line. Modelled on go-jose's jose-util;
// see `jose-cli --help` and tools/cli.cpp.

#include "cli.hpp"

#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#endif

int main(int argc, char** argv) {
#ifdef _WIN32
    // Payloads and plaintexts are bytes: no CRLF translation.
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    std::vector<std::string> args(argv + 1, argv + argc);
    return jose::cli::run(args, {std::cin, std::cout, std::cerr});
}
