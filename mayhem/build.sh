#!/usr/bin/env bash
#
# mayhem/build.sh - build NUT's fuzz harnesses (sanitized, DWARF 3) and its own check programs (plain).
#
# Runs inside the commit image as `mayhem` in /mayhem. Re-runnable and air-gapped: autotools output and
# both build trees live under mayhem/ (gitignored), and everything is resolved from the image.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
FZ="$SRC/mayhem/build-fuzz"
TB="$SRC/mayhem/build-tests"

# Features that need no network or hardware; USB stays on because hidparser.h needs libusb's types.
CONFIGURE_ARGS=(
  --without-docs --without-ssl --with-usb --without-snmp --without-neon --without-ipmi
  --without-modbus --without-gpio --with-serial --with-dev --with-dev-libnutconf
  --disable-shared --enable-static --without-systemdsystemunitdir --without-nut-scanner
)

# 0) autotools: `configure` is gitignored, so a clean tree regenerates it here.
[ -x "$SRC/configure" ] || ./autogen.sh

# 1) The project itself, instrumented (SanCov for the fuzzer, ASan+UBSan) with DWARF <= 3.
mkdir -p "$FZ"
if [ ! -f "$FZ/Makefile" ]; then
  (cd "$FZ" && env -u CFLAGS -u CXXFLAGS -u LDFLAGS ../../configure "${CONFIGURE_ARGS[@]}" \
      --enable-cppunit=no CC="$CC" CXX="$CXX" \
      CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS" \
      CXXFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS" \
      LDFLAGS="$SANITIZER_FLAGS")
fi
make -C "$FZ" -j"$MAYHEM_JOBS"

# 2) Each harness twice: against libFuzzer, and against the run-once standalone driver.
INC=(-I"$SRC/include" -I"$SRC/drivers" -I"$SRC/clients" -I"$FZ/include" -I"$FZ" $(pkg-config --cflags libusb-1.0))
LIBS=(-Wl,--start-group
  "$FZ/clients/.libs/libupsclient.a" "$FZ/common/.libs/libnutconf.a" "$FZ/common/.libs/libcommon.a"
  "$FZ/common/.libs/libparseconf.a" "$FZ/common/.libs/libcommonstr.a"
  -Wl,--end-group -lm -lpthread)

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$FZ/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FZ/standalone_main.o"
# hidparser.c is not in any library: compile it as the check program does, with the sanitizers on.
$CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS "${INC[@]}" -c "$SRC/drivers/hidparser.c" -o "$FZ/hidparser.o"

build_c() {
  local t="$1"; shift
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${INC[@]}" "$SRC/mayhem/$t/$t.c" "$@" \
      "$FZ/lsan_off.o" "${LIBS[@]}" -o "$SRC/$t"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "${INC[@]}" "$SRC/mayhem/$t/$t.c" "$FZ/standalone_main.o" "$@" \
      "$FZ/lsan_off.o" "${LIBS[@]}" -o "$SRC/$t-standalone"
}

build_c parseconf
build_c hidparser "$FZ/hidparser.o"
build_c upsclient_response
build_c upsclient_names

t=nutconf
$CXX -std=c++11 $SANITIZER_FLAGS $DEBUG_FLAGS "${INC[@]}" -c "$SRC/mayhem/$t/$t.cpp" -o "$FZ/$t.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$FZ/$t.o" "$FZ/lsan_off.o" "${LIBS[@]}" -o "$SRC/$t"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$FZ/$t.o" "$FZ/standalone_main.o" "$FZ/lsan_off.o" "${LIBS[@]}" -o "$SRC/$t-standalone"

# 3) NUT's own check programs, built with the project's normal flags (test.sh only runs them).
mkdir -p "$TB"
if [ ! -f "$TB/Makefile" ]; then
  (cd "$TB" && env -u CFLAGS -u CXXFLAGS -u LDFLAGS ../../configure "${CONFIGURE_ARGS[@]}" \
      --enable-cppunit=yes CC="$CC" CXX="$CXX" \
      CFLAGS="$COVERAGE_FLAGS" CXXFLAGS="$COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS")
fi
make -C "$TB" -j"$MAYHEM_JOBS"
make -C "$TB/tests" -j"$MAYHEM_JOBS" check TESTS=
