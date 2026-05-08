#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$ROOT_DIR/scripts/common-env.sh"
zmap_resolve_local_prefixes

usage() {
	cat <<'EOF'
Usage: sh scripts/setup-local.sh [env|check|build|install|all] [cmake args...]

Commands:
  env      Print the resolved local build prefixes.
  check    Validate toolchain and libraries.
  build    Validate the environment and run the build.
  install  Install an existing local build.
  all      Check, build, and install. This is the default.

Environment overrides:
  ZMAP_DEPS_PREFIX     Local prefix that contains headers, libs, pkg-config files,
                       and build tools. Defaults to $PREFIX on Termux, otherwise
                       $HOME/.local.
  ZMAP_BUILD_DIR       Build directory. Defaults to $HOME/build-zmap.
  ZMAP_INSTALL_PREFIX  Install prefix. Defaults to $HOME/.local/zmap.
  JOBS                 Parallel build jobs passed through to scripts/build.sh.
EOF
}

print_env() {
	if is_termux_env; then
		platform=termux
	else
		platform=linux
	fi
	echo "platform: $platform"
	echo "root: $ROOT_DIR"
	echo "deps prefix: $ZMAP_DEPS_PREFIX"
	echo "build dir: $ZMAP_BUILD_DIR"
	echo "install prefix: $ZMAP_INSTALL_PREFIX"
}

run_check() {
	sh "$ROOT_DIR/scripts/bootstrap-env.sh"
}

run_build() {
	sh "$ROOT_DIR/scripts/build.sh" "$@"
}

run_install() {
	sh "$ROOT_DIR/scripts/install-local.sh"
}

command_name=${1:-all}
if [ "$#" -gt 0 ]; then
	shift
fi

case "$command_name" in
env)
	print_env
	;;
check)
	print_env
	run_check
	;;
build)
	print_env
	run_check
	run_build "$@"
	;;
install)
	print_env
	run_install
	;;
all)
	print_env
	run_check
	run_build "$@"
	run_install
	;;
-h|--help|help)
	usage
	;;
*)
	echo "Unknown command: $command_name" >&2
	echo >&2
	usage >&2
	exit 1
	;;
esac
