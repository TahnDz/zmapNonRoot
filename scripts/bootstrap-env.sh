#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT_DIR/scripts/common-env.sh"
zmap_resolve_local_prefixes
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
	echo "  ZMAP_DEPS_PREFIX=$ZMAP_DEPS_PREFIX" >&2
	echo "  PKG_CONFIG_PATH=${PKG_CONFIG_PATH-}" >&2
	echo "  CPPFLAGS=${CPPFLAGS-}" >&2
	echo "  LDFLAGS=${LDFLAGS-}" >&2
	exit 1
fi

echo "Environment OK"
echo "  root: $ROOT_DIR"
echo "  build dir: $ZMAP_BUILD_DIR"
echo "  install prefix: $ZMAP_INSTALL_PREFIX"
echo "  deps prefix: $ZMAP_DEPS_PREFIX"
