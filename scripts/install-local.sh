#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_DIR=${ZMAP_BUILD_DIR:-"$HOME/build-zmap"}
INSTALL_PREFIX=${ZMAP_INSTALL_PREFIX:-"$HOME/.local/zmap"}
DEPS_PREFIX=${ZMAP_DEPS_PREFIX:-"$HOME/.local"}

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

if [ ! -d "$BUILD_DIR" ]; then
	echo "Build directory not found: $BUILD_DIR" >&2
	echo "Run scripts/build.sh first." >&2
	exit 1
fi

cmake --install "$BUILD_DIR" --prefix "$INSTALL_PREFIX"
