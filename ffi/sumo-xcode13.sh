#!/bin/sh
set -ex

: "${LIBNAME:=libuno}"
: "${OUTNAME:=UnoRust}"
: "${TOOLCHAIN:=nightly-2021-07-24}"
: "${PROFILE:=release}"
: "${PROFDIR:=$PROFILE}"

#
# Build an archs table because the triple arch is not the same as lipo arch.
#
ARCHS="
aarch64
x86_64
"
subarchs=$(mktemp -d)
echo "arm64v8" > $subarchs/aarch64
echo "x86_64" > $subarchs/x86_64

mkdir -p libs

#
# Build macOS.
#
lipo_args=""
for ARCH in $ARCHS
do
  TRIPLE="$ARCH-apple-darwin"
  cargo +$TOOLCHAIN build \
      -Z unstable-options --profile $PROFILE \
      -Z build-std \
      --target $TRIPLE

  larch=$(< $subarchs/$ARCH)
  lipo_args="$lipo_args
    -arch $larch ../target/$TRIPLE/$PROFDIR/$LIBNAME.a"
done

lipo -create $lipo_args -output libs/$LIBNAME-macos.a

xc_args="$xc_args
    -library libs/$LIBNAME-macos.a"
xc_args="$xc_args
    -headers include"


#
# Build iOS.
#
TRIPLE=aarch64-apple-ios7.0.0
cargo +$TOOLCHAIN build \
    -Z unstable-options --profile $PROFILE \
    -Z build-std \
    --target xcode13/$TRIPLE.json

cp ../target/$TRIPLE/$PROFDIR/$LIBNAME.a libs/$LIBNAME-ios.a

xc_args="$xc_args
    -library libs/$LIBNAME-ios.a"
xc_args="$xc_args
    -headers include"


#
# Build ios simulator.
#
cargo +$TOOLCHAIN build \
    -Z unstable-options --profile $PROFILE \
    -Z build-std \
    --target aarch64-apple-ios-sim

lipo_args="
    -arch arm64v8 ../target/aarch64-apple-ios-sim/$PROFDIR/$LIBNAME.a"

# The simulator target doesn't end in `-sim` on x86_64
TRIPLE=x86_64-apple-ios7.0.0-sim
cargo +$TOOLCHAIN build \
    -Z unstable-options --profile $PROFILE \
    -Z build-std \
    --target xcode13/$TRIPLE.json

lipo_args="$lipo_args
    -arch x86_64 ../target/$TRIPLE/$PROFDIR/$LIBNAME.a"

lipo -create $lipo_args -output libs/$LIBNAME-ios-sim.a

xc_args="$xc_args
    -library libs/$LIBNAME-ios-sim.a"
xc_args="$xc_args
    -headers include"


#
# Build mac catalyst.
#
lipo_args=""
for ARCH in $ARCHS
do
  TRIPLE="$ARCH-apple-ios-macabi"
  cargo +$TOOLCHAIN build \
      -Z unstable-options --profile $PROFILE \
      -Z build-std \
      --target $TRIPLE

  larch=$(< $subarchs/$ARCH)
  lipo_args="$lipo_args
    -arch $larch ../target/$TRIPLE/$PROFDIR/$LIBNAME.a"
done

lipo -create $lipo_args -output libs/$LIBNAME-ios-macabi.a

xc_args="$xc_args
    -library libs/$LIBNAME-ios-macabi.a"
xc_args="$xc_args
    -headers include"


#
# Build the sumo xcframework.
#
mkdir -p out
xcodebuild -create-xcframework $xc_args -output out/$OUTNAME.xcframework

