#!/bin/sh
# Builds and installs jose2cpp (static; shared; static with the C++20
# expected-lite build; shared with an absolute libdir, as Nix and some distro
# builds set it) into scratch prefixes and builds tests/package against
# each install with CMake and with pkg-config, then against the source tree
# with add_subdirectory. Run from
# the repository root; CI runs it in the "package" job.
#
#   tests/package/run.sh /tmp/jose2cpp-package
#
# Extra arguments to every CMake configure go in CMAKE_ARGS, for example
# CMAKE_ARGS=-DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3 on macOS.
set -eu

work=${1:?usage: tests/package/run.sh WORK_DIR}
src=$(pwd)
rm -rf "$work"
mkdir -p "$work"

for kind in static shared static-cxx20 shared-abs-libdir; do
    prefix="$work/prefix-$kind"
    # The relative-dir builds are configured for the default prefix and
    # installed somewhere else with --prefix, so the CMake package and the
    # .pc file are tested after a move. An absolute libdir fixes the
    # location at configure time, so that build is configured for $prefix.
    shared=OFF std=23 expected=AUTO dirs=""
    case $kind in
        shared) shared=ON ;;
        static-cxx20) std=20 expected=OFF ;;
        shared-abs-libdir)
            shared=ON
            dirs="-DCMAKE_INSTALL_PREFIX=$prefix -DCMAKE_INSTALL_LIBDIR=$prefix/lib" ;;
    esac

    echo "== $kind: build and install"
    # shellcheck disable=SC2086
    cmake -S "$src" -B "$work/build-$kind" -G Ninja ${CMAKE_ARGS:-} \
        -DCMAKE_BUILD_TYPE=Release -DJOSE_BUILD_TESTS=OFF -DBUILD_SHARED_LIBS=$shared \
        -DJOSE_USE_STD_EXPECTED=$expected $dirs
    cmake --build "$work/build-$kind"
    cmake --install "$work/build-$kind" --prefix "$prefix"
    pc=$(find "$prefix" -name jose2cpp.pc)
    if [ -z "$pc" ]; then
        echo "error: no jose2cpp.pc under $prefix" >&2
        exit 1
    fi
    pc_path=$(dirname "$pc")
    libdir=$(dirname "$pc_path")

    echo "== $kind: find_package(jose2cpp)"
    # shellcheck disable=SC2086
    cmake -S "$src/tests/package" -B "$work/consumer-$kind" -G Ninja ${CMAKE_ARGS:-} \
        -DCMAKE_PREFIX_PATH="$prefix"
    cmake --build "$work/consumer-$kind"
    LD_LIBRARY_PATH="$libdir" ctest --test-dir "$work/consumer-$kind" --output-on-failure

    if command -v pkg-config >/dev/null 2>&1; then
        echo "== $kind: pkg-config jose2cpp"
        static=""
        if [ "$shared" = OFF ]; then static=--static; fi
        export_path="$pc_path${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
        # Make sure pkg-config read this install's file and not one from a
        # system directory.
        found=$(PKG_CONFIG_PATH="$export_path" pkg-config --variable=pcfiledir jose2cpp)
        if [ "$found" != "$pc_path" ]; then
            echo "error: pkg-config used $found/jose2cpp.pc, not $pc_path/jose2cpp.pc" >&2
            exit 1
        fi
        flags=$(PKG_CONFIG_PATH="$export_path" pkg-config $static --cflags --libs jose2cpp)
        echo "$flags"
        # shellcheck disable=SC2086
        ${CXX:-c++} -std=c++$std "$src/tests/package/main.cpp" $flags -o "$work/pkgconfig-$kind"
        LD_LIBRARY_PATH="$libdir" "$work/pkgconfig-$kind"
    else
        echo "== $kind: pkg-config not found, skipped"
    fi
done

echo "== add_subdirectory (as FetchContent adds it)"
# shellcheck disable=SC2086
cmake -S "$src/tests/package" -B "$work/consumer-subdir" -G Ninja ${CMAKE_ARGS:-} \
    -DJOSE2CPP_SOURCE_DIR="$src"
cmake --build "$work/consumer-subdir"
ctest --test-dir "$work/consumer-subdir" --output-on-failure
# Pulled in this way, jose2cpp builds no tests and adds no install rules.
sub_install="$work/consumer-subdir/jose2cpp/cmake_install.cmake"
if [ ! -f "$sub_install" ]; then
    echo "error: $sub_install is missing, so the install-rule check can't run" >&2
    exit 1
fi
if grep -q 'file(INSTALL' "$sub_install"; then
    echo "error: jose2cpp added install rules as a subproject" >&2
    exit 1
fi
if [ -d "$work/consumer-subdir/jose2cpp/tests" ]; then
    echo "error: jose2cpp built its tests as a subproject" >&2
    exit 1
fi

echo "== all package checks passed"
