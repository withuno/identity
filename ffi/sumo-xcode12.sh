#!/bin/sh
set -ex

: "${LIBNAME:=libuno}"
: "${OUTNAME:=UnoRust}"
: "${TOOLCHAIN:=nightly-2021-02-06}"
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
    --target xcode12/$TRIPLE.json

cp ../target/$TRIPLE/$PROFDIR/$LIBNAME.a libs/$LIBNAME-ios.a

xc_args="$xc_args
    -library libs/$LIBNAME-ios.a"
xc_args="$xc_args
    -headers include"


#
# Build ios simulator.
#
# I guess we can't build for Xcode12 iOS simulator in rust because llvm doesn't
# have the right target.
#
lipo_args=""
TRIPLE="x86_64-apple-ios7.0.0-sim"
cargo +$TOOLCHAIN build \
    -Z unstable-options --profile $PROFILE \
    -Z build-std \
    --target xcode12/$TRIPLE.json

lipo_args="$lipo_args
  -arch x86_64 ../target/$TRIPLE/$PROFDIR/$LIBNAME.a"

TRIPLE="aarch64-apple-ios14.0-sim"
cargo +$TOOLCHAIN build \
    -Z unstable-options --profile $PROFILE \
    -Z build-std \
    --target xcode12/$TRIPLE.json

lipo_args="$lipo_args
  -arch arm64v8 ../target/$TRIPLE/$PROFDIR/$LIBNAME.a"

lipo -create $lipo_args -output libs/$LIBNAME-ios-sim.a

# !
# Manually add these to the xcframework later.


#
# Build mac catalyst.
#
lipo_args=""
TRIPLE=aarch64-apple-ios14.0-macabi
cargo +$TOOLCHAIN build \
    -Z unstable-options --profile $PROFILE \
    -Z build-std \
    --target xcode12/$TRIPLE.json

lipo_args="$lipo_args
  -arch arm64v8 ../target/$TRIPLE/$PROFDIR/$LIBNAME.a"

TRIPLE=x86_64-apple-ios-macabi
cargo +$TOOLCHAIN build \
    -Z unstable-options --profile $PROFILE \
    -Z build-std \
    --target $TRIPLE

lipo_args="$lipo_args
  -arch x86_64 ../target/$TRIPLE/$PROFDIR/$LIBNAME.a"

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

# Manually add simulator since xcodebuild can't figure its shit out.
#
mkdir -p out/$OUTNAME.xcframework/ios-arm64_x86_64-simulator/Headers
cp include/libuno.h out/$OUTNAME.xcframework/ios-arm64_x86_64-simulator/Headers
cp libs/$LIBNAME-ios-sim.a out/$OUTNAME.xcframework/ios-arm64_x86_64-simulator
plutil -insert AvailableLibraries.0 \
    -xml "$(cat <<-EOF
	<dict>
		<key>HeadersPath</key>
		<string>Headers</string>
		<key>LibraryIdentifier</key>
		<string>ios-arm64_x86_64-simulator</string>
		<key>LibraryPath</key>
		<string>$LIBNAME-ios-sim.a</string>
		<key>SupportedArchitectures</key>
		<array>
			<string>arm64</string>
			<string>x86_64</string>
		</array>
		<key>SupportedPlatform</key>
		<string>ios</string>
		<key>SupportedPlatformVariant</key>
		<string>simulator</string>
	</dict>
	EOF
    )" \
    out/$OUTNAME.xcframework/Info.plist

