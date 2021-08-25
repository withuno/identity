#!/bin/sh

set -x

# libuno-*.a
rm libs/*

# Uno.xcframework
rm -rf out/*

rmdir libs out 
