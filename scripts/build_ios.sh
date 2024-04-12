#!/bin/bash
set -e
cmake -G Xcode -DCMAKE_TOOLCHAIN_FILE=./ios.toolchain.cmake -T buildsystem=1 -DPLATFORM=OS64 -DCMAKE_BUILD_TYPE=Release -DENABLE_SHARED=OFF -DENABLE_BITCODE=1 -S  . -B build_ios

pushd build_ios

xcodebuild -project dlc_all_test.xcodeproj -scheme cfddlc -configuration Release -sdk iphoneos || {
    echo "=========================================================================="
    echo "xcodebuild failed, attempting to copy ecmult_static_context.h and retry..."
    echo "=========================================================================="
    cp -v ../ecmult_static_context.h libwally-core/build/
    xcodebuild -project dlc_all_test.xcodeproj -scheme cfddlc -configuration Release -sdk iphoneos
}
popd
