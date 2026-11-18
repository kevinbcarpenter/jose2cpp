// A main() for compilers without libFuzzer (Apple clang, GCC): runs
// each file given, or every file in each directory given, through the
// target once. Built with sanitizers, it replays the corpus and any crash
// file as a regression test; it doesn't search for new inputs.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size);

namespace {

auto run_file(const std::filesystem::path& path) -> bool {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::fprintf(stderr, "can't open %s\n", path.string().c_str());
        return false;
    }
    const std::vector<char> bytes{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
    LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
    return true;
}

} // namespace

int main(int argc, char** argv) {
    std::size_t runs = 0;
    bool ok = true;
    for (int i = 1; i < argc; ++i) {
        const std::filesystem::path arg = argv[i];
        if (std::filesystem::is_directory(arg)) {
            std::vector<std::filesystem::path> files;
            for (const auto& entry : std::filesystem::directory_iterator(arg))
                if (entry.is_regular_file()) files.push_back(entry.path());
            std::sort(files.begin(), files.end());
            for (const auto& file : files) {
                ok = run_file(file) && ok;
                ++runs;
            }
        } else {
            ok = run_file(arg) && ok;
            ++runs;
        }
    }
    std::printf("replayed %zu inputs\n", runs);
    return ok && runs > 0 ? 0 : 1;
}
