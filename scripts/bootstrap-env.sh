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

setup_local_env() {
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
}

setup_local_env

missing_cmds=
for cmd in cc cmake pkg-config flex byacc gengetopt; do
	if ! command -v "$cmd" >/dev/null 2>&1; then
		missing_cmds="$missing_cmds $cmd"
	fi
done

if [ -n "$missing_cmds" ]; then
	echo "Missing required commands:$missing_cmds" >&2
	echo "Install them into PATH or set ZMAP_DEPS_PREFIX to your local tool prefix." >&2
	exit 1
fi

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/zmap-bootstrap.XXXXXX" 2>/dev/null || mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

cat >"$tmpdir/check.c" <<'EOF'
#include <stdint.h>

#include <Judy.h>
#include <gmp.h>
#include <json-c/json.h>
#include <pcap.h>
#include <unistr.h>

int main(void)
{
	mpz_t value;
	const uint8_t sample[] = {'o', 'k', 0};
	pcap_if_t *ifs = 0;
	json_object *obj = json_object_new_object();
	Pvoid_t judy = (Pvoid_t)0;

	mpz_init(value);
	(void)ifs;
	(void)judy;
	(void)u8_strlen(sample);
	json_object_put(obj);
	mpz_clear(value);
	return 0;
}
EOF

pkg_cflags=
for pkg in gmp libpcap json-c libunistring; do
	if pkg-config --exists "$pkg" 2>/dev/null; then
		pkg_cflags="$pkg_cflags $(pkg-config --cflags "$pkg")"
	fi
done

if ! cc ${CPPFLAGS-} $pkg_cflags "$tmpdir/check.c" \
	${LDFLAGS-} -lJudy -lgmp -lpcap -ljson-c -lunistring \
	-o "$tmpdir/check" >/dev/null 2>&1; then
	echo "Missing required headers or libraries for ZMap." >&2
	echo "Need working local/system installs of: gmp, libpcap, json-c, libunistring, Judy." >&2
	echo "Current search prefixes:" >&2
	echo "  ZMAP_DEPS_PREFIX=$DEPS_PREFIX" >&2
	echo "  PKG_CONFIG_PATH=${PKG_CONFIG_PATH-}" >&2
	echo "  CPPFLAGS=${CPPFLAGS-}" >&2
	echo "  LDFLAGS=${LDFLAGS-}" >&2
	exit 1
fi

echo "Environment OK"
echo "  root: $ROOT_DIR"
echo "  build dir: $BUILD_DIR"
echo "  install prefix: $INSTALL_PREFIX"
echo "  deps prefix: $DEPS_PREFIX"
