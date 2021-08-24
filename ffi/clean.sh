#!/bin/sh

set -x

# libuno-*.a
rm libs/*

# Uno.xcframework
rm out/* 

rmdir libs out 
