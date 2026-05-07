#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_DIR=${ZMAP_BUILD_DIR:-"$HOME/build-zmap"}
INSTALL_PREFIX=${ZMAP_INSTALL_PREFIX:-"$HOME/.local/zmap"}
DEPS_PREFIX=${ZMAP_DEPS_PREFIX:-"$HOME/.local"}
CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE:-RelWithDebInfo}
ENABLE_DEVELOPMENT=${ENABLE_DEVELOPMENT:-OFF}
ENABLE_LOG_TRACE=${ENABLE_LOG_TRACE:-OFF}
JOBS=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)}

prepend_path() {
	var_name=$1
	value=$2
	eval current_value=\${$var_name-}
	case ":$current_value:" in
	*:"$value":*)
		;;
	*)
		if [ -n "$current_value" ]; then
			eval "export $var_name=\"\$value:\$current_value\""
		else
			eval "export $var_name=\"\$value\""
		fi
		;;
	esac
}

append_flag() {
	var_name=$1
	value=$2
	eval current_value=\${$var_name-}
	case " $current_value " in
	*" $value "*)
		;;
	*)
		if [ -n "$current_value" ]; then
			eval "export $var_name=\"\$current_value \$value\""
		else
			eval "export $var_name=\"\$value\""
		fi
		;;
	esac
}

prepend_path PATH "$DEPS_PREFIX/bin"
if [ -d "$DEPS_PREFIX/lib/pkgconfig" ]; then
	prepend_path PKG_CONFIG_PATH "$DEPS_PREFIX/lib/pkgconfig"
fi
if [ -d "$DEPS_PREFIX/lib64/pkgconfig" ]; then
	prepend_path PKG_CONFIG_PATH "$DEPS_PREFIX/lib64/pkgconfig"
fi
if [ -d "$DEPS_PREFIX/share/pkgconfig" ]; then
	prepend_path PKG_CONFIG_PATH "$DEPS_PREFIX/share/pkgconfig"
fi
if [ -d "$DEPS_PREFIX/include" ]; then
	append_flag CPPFLAGS "-I$DEPS_PREFIX/include"
fi
if [ -d "$DEPS_PREFIX/lib" ]; then
	append_flag LDFLAGS "-L$DEPS_PREFIX/lib"
fi
if [ -d "$DEPS_PREFIX/lib64" ]; then
	append_flag LDFLAGS "-L$DEPS_PREFIX/lib64"
fi

export GIT_DISCOVERY_ACROSS_FILESYSTEM=1

sh "$ROOT_DIR/scripts/bootstrap-env.sh" >/dev/null

cmake -S "$ROOT_DIR" -B "$BUILD_DIR" \
	-DCMAKE_BUILD_TYPE="$CMAKE_BUILD_TYPE" \
	-DENABLE_DEVELOPMENT="$ENABLE_DEVELOPMENT" \
	-DENABLE_LOG_TRACE="$ENABLE_LOG_TRACE" \
	-DRESPECT_INSTALL_PREFIX_CONFIG=ON \
	-DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
	"$@"

cmake --build "$BUILD_DIR" -j"$JOBS"
