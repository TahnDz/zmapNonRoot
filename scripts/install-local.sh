#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT_DIR/scripts/common-env.sh"
zmap_resolve_local_prefixes
setup_local_env

if [ ! -d "$ZMAP_BUILD_DIR" ]; then
	echo "Build directory not found: $ZMAP_BUILD_DIR" >&2
	echo "Run scripts/build.sh first." >&2
	exit 1
fi

cmake --install "$ZMAP_BUILD_DIR" --prefix "$ZMAP_INSTALL_PREFIX"
