#!/bin/sh

set -x

# libuno-*.a
rm libs/*

# Uno.xcframework
rm -rf out/UnoRust.xcframework

rmdir libs out 
