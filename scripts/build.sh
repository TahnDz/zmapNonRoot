#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT_DIR/scripts/common-env.sh"
zmap_resolve_local_prefixes
CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE:-RelWithDebInfo}
ENABLE_DEVELOPMENT=${ENABLE_DEVELOPMENT:-OFF}
ENABLE_LOG_TRACE=${ENABLE_LOG_TRACE:-OFF}
JOBS=${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)}

setup_local_env

export GIT_DISCOVERY_ACROSS_FILESYSTEM=1

sh "$ROOT_DIR/scripts/bootstrap-env.sh" >/dev/null

cmake -S "$ROOT_DIR" -B "$ZMAP_BUILD_DIR" \
	-DCMAKE_BUILD_TYPE="$CMAKE_BUILD_TYPE" \
	-DENABLE_DEVELOPMENT="$ENABLE_DEVELOPMENT" \
	-DENABLE_LOG_TRACE="$ENABLE_LOG_TRACE" \
	-DRESPECT_INSTALL_PREFIX_CONFIG=ON \
	-DCMAKE_INSTALL_PREFIX="$ZMAP_INSTALL_PREFIX" \
	"$@"

cmake --build "$ZMAP_BUILD_DIR" -j"$JOBS"
