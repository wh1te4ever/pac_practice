#!/bin/zsh
clang -O0 -target arm64e-apple-macos11.0 -arch arm64e -fobjc-arc -fno-stack-protector -Wl,-no_pie -o simplepac main.c
codesign -s - --force --deep --timestamp=none  ./simplepac
