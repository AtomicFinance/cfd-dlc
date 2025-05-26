# Get the full path to the project root directory
PROJECT_ROOT=$(cd "$(dirname "$0")"/.. && pwd)

# Use the full path for the build directories
IOS_BUILD_DIR="$PROJECT_ROOT/build_ios/Release"
SIM_BUILD_DIR="$PROJECT_ROOT/build_sim/Release"

lipo -create "$IOS_BUILD_DIR/libunivalue.a" "$SIM_BUILD_DIR/libunivalue.a" -output libunivalue.a
lipo -create "$IOS_BUILD_DIR/libwally.a" "$SIM_BUILD_DIR/libwally.a" -output libwally.a
lipo -create "$IOS_BUILD_DIR/libcfd.a" "$SIM_BUILD_DIR/libcfd.a" -output libcfd.a
lipo -create "$IOS_BUILD_DIR/libcfdcore.a" "$SIM_BUILD_DIR/libcfdcore.a" -output libcfdcore.a
lipo -create "$IOS_BUILD_DIR/libcfddlc.a" "$SIM_BUILD_DIR/libcfddlc.a" -output libcfddlc.a
