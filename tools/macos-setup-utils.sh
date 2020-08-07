

#
# Do we have permission to write in /usr/local?
#
# If so, assume we have permission to write in its subdirectories.
# (If that's not the case, this test needs to check the subdirectories
# as well.)
#
# If not, do "make install", "make uninstall", the removes for Lua,
# and the renames of [g]libtool* with sudo.
#
if [ -w /usr/local ]
then
    DO_MAKE_INSTALL="make install"
    DO_MAKE_UNINSTALL="make uninstall"
    DO_RM="rm"
    DO_MV="mv"
else
    DO_MAKE_INSTALL="sudo make install"
    DO_MAKE_UNINSTALL="sudo make uninstall"
    DO_RM="sudo rm"
    DO_MV="sudo mv"
fi

# This script is meant to be run in the source root.  The following
# code will attempt to get you there, but is not perfect (particulary
# if someone copies the script).

topdir=`pwd`/`dirname $0`/..
cd $topdir

# Preference of the support libraries directory:
#   ${MACOSX_SUPPORT_LIBS}
#   ../macosx-support-libs
#   ./macosx-support-libs (default if none exists)
if [ ! -d "${MACOSX_SUPPORT_LIBS}" ]; then
  unset MACOSX_SUPPORT_LIBS
fi
if [ -d ../macosx-support-libs ]; then
  MACOSX_SUPPORT_LIBS=${MACOSX_SUPPORT_LIBS-../macosx-support-libs}
else
  MACOSX_SUPPORT_LIBS=${MACOSX_SUPPORT_LIBS-./macosx-support-libs}
fi

#
# If we have SDKs available, the default target OS is the major version
# of the one we're running; get that and strip off the third component
# if present.
#
for i in /Developer/SDKs \
    /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs \
    /Library/Developer/CommandLineTools/SDKs
do
    if [ -d "$i" ]
    then
        min_osx_target=`sw_vers -productVersion | sed 's/\([0-9]*\)\.\([0-9]*\)\.[0-9]*/\1.\2/'`
        break
    fi
done

#
# Parse command-line flags:
#
# -h - print help.
# -t <target> - build libraries so that they'll work on the specified
# version of macOS and later versions.
# -u - do an uninstall.
# -n - download all packages, but don't build or install.
#

no_build=false

while getopts ht:un name
do
    case $name in
    u)
        do_uninstall=yes
        ;;
    n)
        no_build=true
        ;;
    t)
        min_osx_target="$OPTARG"
        ;;
    h|?)
        echo "Usage: macos-setup.sh [ -t <target> ] [ -u ] [ -n ]" 1>&1
        exit 0
        ;;
    esac
done

#
# Get the version numbers of installed packages, if any.
#
if [ -d "${MACOSX_SUPPORT_LIBS}" ]
then
    cd "${MACOSX_SUPPORT_LIBS}"

    installed_xz_version=`ls xz-*-done 2>/dev/null | sed 's/xz-\(.*\)-done/\1/'`
    installed_lzip_version=`ls lzip-*-done 2>/dev/null | sed 's/lzip-\(.*\)-done/\1/'`
    installed_autoconf_version=`ls autoconf-*-done 2>/dev/null | sed 's/autoconf-\(.*\)-done/\1/'`
    installed_automake_version=`ls automake-*-done 2>/dev/null | sed 's/automake-\(.*\)-done/\1/'`
    installed_libtool_version=`ls libtool-*-done 2>/dev/null | sed 's/libtool-\(.*\)-done/\1/'`
    installed_cmake_version=`ls cmake-*-done 2>/dev/null | sed 's/cmake-\(.*\)-done/\1/'`
    installed_ninja_version=`ls ninja-*-done 2>/dev/null | sed 's/ninja-\(.*\)-done/\1/'`
    installed_asciidoctor_version=`ls asciidoctor-*-done 2>/dev/null | sed 's/asciidoctor-\(.*\)-done/\1/'`
    installed_asciidoctorpdf_version=`ls asciidoctorpdf-*-done 2>/dev/null | sed 's/asciidoctorpdf-\(.*\)-done/\1/'`
    installed_gettext_version=`ls gettext-*-done 2>/dev/null | sed 's/gettext-\(.*\)-done/\1/'`
    installed_pkg_config_version=`ls pkg-config-*-done 2>/dev/null | sed 's/pkg-config-\(.*\)-done/\1/'`
    installed_glib_version=`ls glib-*-done 2>/dev/null | sed 's/glib-\(.*\)-done/\1/'`
    installed_qt_version=`ls qt-*-done 2>/dev/null | sed 's/qt-\(.*\)-done/\1/'`
    installed_libsmi_version=`ls libsmi-*-done 2>/dev/null | sed 's/libsmi-\(.*\)-done/\1/'`
    installed_libgpg_error_version=`ls libgpg-error-*-done 2>/dev/null | sed 's/libgpg-error-\(.*\)-done/\1/'`
    installed_libgcrypt_version=`ls libgcrypt-*-done 2>/dev/null | sed 's/libgcrypt-\(.*\)-done/\1/'`
    installed_gmp_version=`ls gmp-*-done 2>/dev/null | sed 's/gmp-\(.*\)-done/\1/'`
    installed_nettle_version=`ls nettle-*-done 2>/dev/null | sed 's/nettle-\(.*\)-done/\1/'`
    installed_gnutls_version=`ls gnutls-*-done 2>/dev/null | sed 's/gnutls-\(.*\)-done/\1/'`
    installed_lua_version=`ls lua-*-done 2>/dev/null | sed 's/lua-\(.*\)-done/\1/'`
    installed_snappy_version=`ls snappy-*-done 2>/dev/null | sed 's/snappy-\(.*\)-done/\1/'`
    installed_zstd_version=`ls zstd-*-done 2>/dev/null | sed 's/zstd-\(.*\)-done/\1/'`
    installed_libxml2_version=`ls libxml2-*-done 2>/dev/null | sed 's/libxml2-\(.*\)-done/\1/'`
    installed_lz4_version=`ls lz4-*-done 2>/dev/null | sed 's/lz4-\(.*\)-done/\1/'`
    installed_sbc_version=`ls sbc-*-done 2>/dev/null | sed 's/sbc-\(.*\)-done/\1/'`
    installed_maxminddb_version=`ls maxminddb-*-done 2>/dev/null | sed 's/maxminddb-\(.*\)-done/\1/'`
    installed_cares_version=`ls c-ares-*-done 2>/dev/null | sed 's/c-ares-\(.*\)-done/\1/'`
    installed_libssh_version=`ls libssh-*-done 2>/dev/null | sed 's/libssh-\(.*\)-done/\1/'`
    installed_nghttp2_version=`ls nghttp2-*-done 2>/dev/null | sed 's/nghttp2-\(.*\)-done/\1/'`
    installed_nghttp3_version=`ls nghttp3-*-done 2>/dev/null | sed 's/nghttp3-\(.*\)-done/\1/'`
    installed_libtiff_version=`ls tiff-*-done 2>/dev/null | sed 's/tiff-\(.*\)-done/\1/'`
    installed_spandsp_version=`ls spandsp-*-done 2>/dev/null | sed 's/spandsp-\(.*\)-done/\1/'`
    installed_speexdsp_version=`ls speexdsp-*-done 2>/dev/null | sed 's/speexdsp-\(.*\)-done/\1/'`
    installed_bcg729_version=`ls bcg729-*-done 2>/dev/null | sed 's/bcg729-\(.*\)-done/\1/'`
    installed_ilbc_version=`ls ilbc-*-done 2>/dev/null | sed 's/ilbc-\(.*\)-done/\1/'`
    installed_python3_version=`ls python3-*-done 2>/dev/null | sed 's/python3-\(.*\)-done/\1/'`
    installed_brotli_version=`ls brotli-*-done 2>/dev/null | sed 's/brotli-\(.*\)-done/\1/'`
    installed_minizip_version=`ls minizip-*-done 2>/dev/null | sed 's/minizip-\(.*\)-done/\1/'`
    installed_sparkle_version=`ls sparkle-*-done 2>/dev/null | sed 's/sparkle-\(.*\)-done/\1/'`

    cd $topdir
fi

if [ "$do_uninstall" = "yes" ]
then
    uninstall_all
    exit 0
fi

#
# Configure scripts tend to set CFLAGS and CXXFLAGS to "-g -O2" if
# invoked without CFLAGS or CXXFLAGS being set in the environment.
#
# However, we *are* setting them in the environment, for our own
# nefarious purposes, so start them out as "-g -O2".
#
CFLAGS="-g -O2"
CXXFLAGS="-g -O2"

# if no make options are present, set default options
if [ -z "$MAKE_BUILD_OPTS" ] ; then
    # by default use 1.5x number of cores for parallel build
    MAKE_BUILD_OPTS="-j $(( $(sysctl -n hw.logicalcpu) * 3 / 2))"
fi

#
# If we have a target release, look for the oldest SDK that's for an
# OS equal to or later than that one, and build libraries against it
# rather than against the headers and, more importantly, libraries
# that come with the OS, so that we don't end up with support libraries
# that only work on the OS version on which we built them, not earlier
# versions of the same release, or earlier releases if the minimum is
# earlier.
#
if [ ! -z "$min_osx_target" ]
then
    #
    # Get the real version - strip off the "10.".
    #
    deploy_real_version=`echo "$min_osx_target" | sed -n 's/10\.\(.*\)/\1/p'`

    #
    # Search each directory that might contain SDKs.
    #
    sdkpath=""
    for sdksdir in /Developer/SDKs \
        /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs \
        /Library/Developer/CommandLineTools/SDKs
    do
        #
        # Get a list of all the SDKs.
        #
        if ! test -d "$sdksdir"
        then
            #
            # There is no directory with that name.
            # Move on to the next one in the list, if any.
            #
            continue
        fi

        #
        # Get a list of all the SDKs in that directory, if any.
        #
        sdklist=`(cd "$sdksdir"; ls -d MacOSX10.[0-9]*.sdk 2>/dev/null)`

        for sdk in $sdklist
        do
            #
            # Get the real version for this SDK.
            #
            sdk_real_version=`echo "$sdk" | sed -n 's/MacOSX10\.\(.*\)\.sdk/\1/p'`

            #
            # Is it for the deployment target or some later release?
            #
            if test "$sdk_real_version" -ge "$deploy_real_version"
            then
                #
                # Yes, use it.
                #
                sdkpath="$sdksdir/$sdk"
                break 2
            fi
        done
    done

    if [ -z "$sdkpath" ]
    then
        echo "macos-setup.sh: Couldn't find an SDK for macOS $min_osx_target or later" 1>&2
        exit 1
    fi

    SDKPATH="$sdkpath"
    echo "Using the 10.$sdk_real_version SDK"

    #
    # Make sure there are links to /usr/local/include and /usr/local/lib
    # in the SDK's usr/local.
    #
    if [ ! -e $SDKPATH/usr/local/include ]
    then
        if [ ! -d $SDKPATH/usr/local ]
        then
            sudo mkdir $SDKPATH/usr/local
        fi
        sudo ln -s /usr/local/include $SDKPATH/usr/local/include
    fi
    if [ ! -e $SDKPATH/usr/local/lib ]
    then
        if [ ! -d $SDKPATH/usr/local ]
        then
            sudo mkdir $SDKPATH/usr/local
        fi
        sudo ln -s /usr/local/lib $SDKPATH/usr/local/lib
    fi

    #
    # Set the minimum OS version for which to build to the specified
    # minimum target OS version, so we don't, for example, end up using
    # linker features supported by the OS verson on which we're building
    # but not by the target version.
    #
    VERSION_MIN_FLAGS="-mmacosx-version-min=$min_osx_target"

    #
    # Compile and link against the SDK.
    #
    SDKFLAGS="-isysroot $SDKPATH"

fi

export CFLAGS
export CXXFLAGS

#
# You need Xcode or the command-line tools installed to get the compilers.
#
if [ ! -x /usr/bin/xcodebuild ]; then
    echo "Please install Xcode first (should be available on DVD or from the Mac App Store)."
    exit 1
fi

if [ "$QT_VERSION" ]; then
    #
    # We need Xcode, not just the command-line tools, installed to build
    # Qt.
    #
    # At least with Xcode 8, /usr/bin/xcodebuild --help fails if only
    # the command-line tools are installed and succeeds if Xcode is
    # installed.  Unfortunately, it fails *with* Xcode 3, but
    # /usr/bin/xcodebuild -version works with that and with Xcode 8.
    # Hopefully it fails with only the command-line tools installed.
    #
    if /usr/bin/xcodebuild -version >/dev/null 2>&1; then
        :
    else
        echo "Please install Xcode first (should be available on DVD or from the Mac App Store)."
        echo "The command-line build tools are not sufficient to build Qt."
        exit 1
    fi
fi

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig

#
# Do all the downloads and untarring in a subdirectory, so all that
# stuff can be removed once we've installed the support libraries.

if [ ! -d "${MACOSX_SUPPORT_LIBS}" ]
then
    mkdir "${MACOSX_SUPPORT_LIBS}" || exit 1
fi
cd "${MACOSX_SUPPORT_LIBS}"

install_all

echo ""

#
# Indicate what paths to use for pkg-config and cmake.
#
pkg_config_path=/usr/local/lib/pkgconfig
if [ "$QT_VERSION" ]; then
    qt_base_path=$HOME/Qt$QT_VERSION/$QT_VERSION/clang_64
    pkg_config_path="$pkg_config_path":"$qt_base_path/lib/pkgconfig"
    CMAKE_PREFIX_PATH="$CMAKE_PREFIX_PATH":"$qt_base_path/lib/cmake"
fi

if $no_build; then
    echo "All required dependencies downloaded. Run without -n to install them."
    exit 0
fi

echo "You are now prepared to build Wireshark."
echo
echo "To build:"
echo
echo "export PKG_CONFIG_PATH=$pkg_config_path"
echo "export CMAKE_PREFIX_PATH=$CMAKE_PREFIX_PATH"
echo "export PATH=$PATH:$qt_base_path/bin"
echo
echo "mkdir build; cd build"
if [ ! -z "$NINJA_VERSION" ]; then
    echo "cmake -G Ninja .."
    echo "ninja app_bundle"
    echo "ninja install/strip"
else
    echo "cmake .."
    echo "make $MAKE_BUILD_OPTS app_bundle"
    echo "make install/strip"
fi
echo
echo "Make sure you are allowed capture access to the network devices"
echo "See: https://wiki.wireshark.org/CaptureSetup/CapturePrivileges"
echo

exit 0
