#!/bin/bash
set -e
cmake -G Xcode -DCMAKE_TOOLCHAIN_FILE=./ios.toolchain.cmake -T buildsystem=1 -DPLATFORM=SIMULATOR64 -DCMAKE_BUILD_TYPE=Release -DENABLE_SHARED=OFF -DENABLE_BITCODE=1 -S  . -B build_sim

pushd build_sim

xcodebuild -project dlc_all_test.xcodeproj -scheme cfddlc -configuration Release -sdk iphonesimulator || {
    echo "=========================================================================="
    echo "xcodebuild failed, attempting to copy ecmult_static_context.h and retry..."
    echo "=========================================================================="
    cp -v ../ecmult_static_context.h libwally-core/build/
    xcodebuild -project dlc_all_test.xcodeproj -scheme cfddlc -configuration Release -sdk iphonesimulator
}
popd
