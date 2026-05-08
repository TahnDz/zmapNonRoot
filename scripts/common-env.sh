#!/bin/sh

set -eu

zmap_root_dir() {
	CDPATH= cd -- "$(dirname -- "$0")/.." && pwd
}

is_termux_env() {
	if [ -n "${TERMUX_VERSION-}" ]; then
		return 0
	fi
	if [ -n "${PREFIX-}" ]; then
		case "$PREFIX" in
		*/com.termux/*)
			return 0
			;;
		esac
	fi
	if command -v getprop >/dev/null 2>&1; then
		if [ "$(getprop ro.build.version.release 2>/dev/null || true)" ]; then
			case "${PREFIX-}" in
			*/com.termux/*)
				return 0
				;;
			esac
		fi
	fi
	return 1
}

zmap_default_build_dir() {
	printf '%s\n' "${ZMAP_BUILD_DIR:-$HOME/build-zmap}"
}

zmap_default_install_prefix() {
	printf '%s\n' "${ZMAP_INSTALL_PREFIX:-$HOME/.local/zmap}"
}

zmap_default_deps_prefix() {
	if [ -n "${ZMAP_DEPS_PREFIX-}" ]; then
		printf '%s\n' "$ZMAP_DEPS_PREFIX"
		return 0
	fi
	if is_termux_env && [ -n "${PREFIX-}" ]; then
		printf '%s\n' "$PREFIX"
		return 0
	fi
	printf '%s\n' "$HOME/.local"
}

zmap_resolve_local_prefixes() {
	ZMAP_BUILD_DIR=$(zmap_default_build_dir)
	ZMAP_INSTALL_PREFIX=$(zmap_default_install_prefix)
	ZMAP_DEPS_PREFIX=$(zmap_default_deps_prefix)
	export ZMAP_BUILD_DIR ZMAP_INSTALL_PREFIX ZMAP_DEPS_PREFIX
}

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

setup_local_env() {
	prepend_path PATH "$ZMAP_DEPS_PREFIX/bin"
	if [ -d "$ZMAP_DEPS_PREFIX/lib/pkgconfig" ]; then
		prepend_path PKG_CONFIG_PATH "$ZMAP_DEPS_PREFIX/lib/pkgconfig"
	fi
	if [ -d "$ZMAP_DEPS_PREFIX/lib64/pkgconfig" ]; then
		prepend_path PKG_CONFIG_PATH "$ZMAP_DEPS_PREFIX/lib64/pkgconfig"
	fi
	if [ -d "$ZMAP_DEPS_PREFIX/share/pkgconfig" ]; then
		prepend_path PKG_CONFIG_PATH "$ZMAP_DEPS_PREFIX/share/pkgconfig"
	fi
	if [ -d "$ZMAP_DEPS_PREFIX/include" ]; then
		append_flag CPPFLAGS "-I$ZMAP_DEPS_PREFIX/include"
	fi
	if [ -d "$ZMAP_DEPS_PREFIX/lib" ]; then
		append_flag LDFLAGS "-L$ZMAP_DEPS_PREFIX/lib"
	fi
	if [ -d "$ZMAP_DEPS_PREFIX/lib64" ]; then
		append_flag LDFLAGS "-L$ZMAP_DEPS_PREFIX/lib64"
	fi
}
