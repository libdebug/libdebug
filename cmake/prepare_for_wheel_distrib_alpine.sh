#!/bin/bash

# This file should not go here, but I've not found a better place yet.
# Intended for Musl-based Alpine Linux

# Install git
apk add git

# Clone the libdwarf code repository
git clone https://github.com/davea42/libdwarf-code.git --depth 1

# Install the required packages for building libdwarf
apk add gcc g++ make autoconf automake libtool pkgconf zstd-dev zlib-dev

# Change to the libdwarf directory
cd libdwarf-code

# Run the autogen script to generate the configure script
env -i sh autogen.sh

# Configure the build system
CFLAGS="-O2" ./configure --enable-shared --disable-dependency-tracking

# Build the library
make -j$(nproc)

# Install the library
make install

# Go back to the home directory
cd ..

# Install elfutils
apk add elfutils-dev binutils-dev
