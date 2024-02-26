#!/bin/bash

echo "Building Fedora..."
docker build -f dockerfiles/fedora.Dockerfile -t libdebug_test_fedora --quiet ../
if [ $? -eq 0 ]; then
    echo "Fedora build successful"
else
    echo "Fedora build failed"
    exit 1
fi

echo "Building Ubuntu..."
docker build -f dockerfiles/ubuntu.Dockerfile -t libdebug_test_ubuntu --quiet ../
if [ $? -eq 0 ]; then
    echo "Ubuntu build successful"
else
    echo "Ubuntu build failed"
    exit 1
fi

echo "Building Arch..."
docker build -f dockerfiles/archlinux.Dockerfile -t libdebug_test_archlinux --quiet ../
if [ $? -eq 0 ]; then
    echo "Arch build successful"
else
    echo "Arch build failed"
    exit 1
fi

echo "Building Debian..."
docker build -f dockerfiles/debian.Dockerfile -t libdebug_test_debian --quiet ../
if [ $? -eq 0 ]; then
    echo "Debian build successful"
else
    echo "Debian build failed"
    exit 1
fi

echo "Testing Fedora"
docker run -it --rm --privileged libdebug_test_fedora

echo "Testing Ubuntu"
docker run -it --rm --privileged libdebug_test_ubuntu

echo "Testing Arch"
docker run -it --rm --privileged libdebug_test_archlinux

echo "Testing Debian"
docker run -it --rm --privileged libdebug_test_debian

