#!/bin/bash
# Setup development environment on macOS (tested with 10.6.8 and Xcode
# 3.2.6 and with 10.12.4 and Xcode 8.3).
#
# Copyright 2011 Michael Tuexen, Joerg Mayer, Guy Harris (see AUTHORS file)
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

shopt -s extglob

#
# Get the major version of Darwin, so we can check the major macOS
# version.
#
DARWIN_MAJOR_VERSION=`uname -r | sed 's/\([0-9]*\).*/\1/'`

#
# To make this work on Leopard (rather than working *on* Snow Leopard
# when building *for* Leopard) will take more work.
#
if [[ $DARWIN_MAJOR_VERSION -le 9 ]]; then
    echo "This script does not support any versions of macOS before Snow Leopard" 1>&2
    exit 1
fi

NGHTTP3_VERSION=draft-28

#
# Ninja isn't required, as make is provided with Xcode, but it is
install_nghttp3() {
    if [ "$NGHTTP3_VERSION" -a ! -f nghttp3-$NGHTTP3_VERSION-done ] ; then
        echo "Downloading, building, and installing nghttp2:"
        [ -f nghttp3-$NGHTTP3_VERSION.tar.xz ] || curl -L -O https://github.com/ngtcp2/nghttp3/archive/$NGHTTP3_VERSION.zip || exit 1
        $no_build && echo "Skipping installation" && return
        unzip $NGHTTP3_VERSION.zip || exit 1
        cd nghttp3-$NGHTTP3_VERSION
        CFLAGS="$CFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" CXXFLAGS="$CXXFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" LDFLAGS="$LDFLAGS $VERSION_MIN_FLAGS $SDKFLAGS" cmake -G 'Unix Makefiles'|| exit 1
        echo "Building with \"make $MAKE_BUILD_OPTS\""
        make $MAKE_BUILD_OPTS || exit 1
        echo "Installing with \"$DO_MAKE_INSTALL\""
        $DO_MAKE_INSTALL || exit 1
        cd ..
        touch nghttp3-$NGHTTP3_VERSION-done
    fi
}

uninstall_nghttp3() {
    if [ ! -z "$installed_nghttp3_version" ] ; then
        echo "Uninstalling nghttp3:"
        cd nghttp2-$installed_nghttp3_version
        $DO_MAKE_UNINSTALL || exit 1
        make distclean || exit 1
        cd ..
        rm nghttp3-$installed_nghttp3_version-done

        if [ "$#" -eq 1 -a "$1" = "-r" ] ; then
            #
            # Get rid of the previously downloaded and unpacked version.
            #
            rm -rf nghttp3-$installed_nghttp3_version
            rm -rf nghttp3-$installed_nghttp3_version.tar.xz
        fi

        installed_nghttp3_version=""
    fi
}


install_all() {

    if [ ! -z "$installed_nghttp3_version" -a \
              "$installed_nghttp3_version" != "$NGHTTP3_VERSION" ] ; then
        echo "Installed nghttp3 version is $installed_nghttp3_version"
        if [ -z "$NGHTTP3_VERSION" ] ; then
            echo "nghttp3 is not requested"
        else
            echo "Requested nghttp3 version is $NGHTTP3_VERSION"
        fi
        uninstall_nghttp3 -r
    fi

    install_nghttp3
}

uninstall_all() { 
    uninstall_nghttp3
}

source `pwd`/`dirname $0`/macos-setup-utils.sh
