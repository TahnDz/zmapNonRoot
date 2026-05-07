# Installing and Building ZMap

## Installing via Package Manager

ZMap operates on GNU/Linux, macOS, and BSD. The latest stable version may be available in package managers.

| OS                                        |                         |
| ----------------------------------------- | ----------------------- |
| Fedora 19+ or EPEL 6+                     | `yum install zmap` |
| Debian 8+ or Ubuntu 14.04+                | `apt install zmap` |
| Gentoo                                    | `emerge zmap`      |
| macOS (using [Homebrew](https://brew.sh)) | `brew install zmap`     |
| macOS (using [MacPorts](https://macports.org)) | `port install zmap`|
| Arch Linux                                | `pacman -S zmap`   |

## Building from Source

### Installing ZMap Dependencies

ZMap has the following dependencies:

  - [CMake](http://www.cmake.org/) - Cross-platform, open-source build system
  - [GMP](http://gmplib.org/) - Arbitrary precision arithmetic
  - [gengetopt](http://www.gnu.org/software/gengetopt/gengetopt.html) - Command line option parsing
  - [libpcap](http://www.tcpdump.org/) - User-level packet capture library
  - [flex](http://flex.sourceforge.net/) and [byacc](http://invisible-island.net/byacc/) - Lexer and parser generator
  - [json-c](https://github.com/json-c/json-c/) - JSON parsing and output
  - [libunistring](https://www.gnu.org/software/libunistring/) - Unicode string library
  - [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/) - compiler and library helper tool
  - [libjudy](https://judy.sourceforge.net/) - Judy Array for packet de-duplication

The source tree now contains an unprivileged runtime backend for compatible probe modules on Linux and Android/Termux, but the build dependencies are unchanged. The privileged backend is still built and remains the only option for modules that require raw packet transmission or libpcap capture.

Install the required dependencies with the following commands.

* On Debian-based systems (including Ubuntu):
   ```sh
   sudo apt-get install build-essential cmake libgmp3-dev gengetopt libpcap-dev flex byacc libjson-c-dev pkg-config libunistring-dev libjudy-dev
   ```

* On RHEL- and Fedora-based systems (including CentOS):
   ```sh
   sudo dnf install gcc cmake gmp-devel gengetopt libpcap-devel flex byacc json-c-devel libunistring-devel Judy-devel
   ```
* On Arch systems
   ```sh
   pacman -S base-devel cmake gmp gengetopt libpcap flex byacc json-c pkg-config libunistring judy python
   ```

* On Gentoo systems
   ```sh
   emerge sys-devel/binutils dev-libs/gmp dev-util/gengetopt net-libs/libpcap sys-devel/flex dev-util/byacc dev-libs/json-c dev-util/pkgconf dev-libs/libunistring dev-libs/judy
   ```

* On macOS systems (using [Homebrew](https://brew.sh/)):
  ```sh
  brew install pkg-config cmake gmp gengetopt json-c byacc libunistring judy
  ```

* On macOS systems (using [MacPorts](https://macports.org/)):
  ```
  sudo port install cmake byacc flex gengetopt pkgconfig gmp libpcap json-c libunistring judy
  ```

* To launch a shell inside a Docker container with the build dependencies
  mounted at `/src`:
  ```sh
  docker run -it -v $(pwd):/src zmap/builder
  ```

### Building and Installing ZMap

Once these prerequisites are installed, clone the ZMap repository and navigate into the cloned directory.
  ```sh
  cd zmap
  ```
Then, ZMap can be compiled by running:
  ```sh
  cmake .
  make -j4
  ```

and then installed via `sudo make install`.

For a user-local build that does not assume `sudo`, `apt`, or any system-wide
install location, use the helper scripts in `scripts/`:

```sh
sh scripts/bootstrap-env.sh
sh scripts/build.sh
sh scripts/install-local.sh
```

By default these build in `$HOME/build-zmap`, install into `$HOME/.local/zmap`,
and also search `$HOME/.local` for locally installed headers, libraries,
pkg-config files, and tools. You can override the paths with:

```sh
ZMAP_DEPS_PREFIX=$HOME/.local \
ZMAP_BUILD_DIR=$HOME/build-zmap \
ZMAP_INSTALL_PREFIX=$HOME/.local/zmap \
sh scripts/build.sh

ZMAP_BUILD_DIR=$HOME/build-zmap \
ZMAP_INSTALL_PREFIX=$HOME/.local/zmap \
sh scripts/install-local.sh
```

This flow is intended for Termux and other non-root Linux environments where
dependencies are already available under a user-owned prefix.

### Running without root on Linux or Termux

When raw sockets are unavailable, ZMap will automatically fall back to `--unprivileged` for compatible probe modules. You can also request that path explicitly:

```sh
zmap --unprivileged -p 80
```

This mode is designed for environments such as Termux and other non-root Linux setups. It currently supports `tcp_synscan` and compatible UDP modules such as `udp`, `dns`, `ntp`, `upnp`, and `bacnet`. It does not preserve all raw-packet semantics and cannot replace the privileged backend for modules that depend on custom packet injection or passive packet capture.

### Development Notes

- Enabling development turns on debug symbols, and turns off optimizations.
Release builds should be built with `-DENABLE_DEVELOPMENT=OFF`.

- Enabling `log_trace` can have a major performance impact and should not be used
except during early development. Release builds should be built with `-DENABLE_LOG_TRACE=OFF`.

- Building packages for some systems like Fedora and RHEL requires a user-definable
directory (buildroot) to put files. The way to respect this prefix is to run cmake
with `-DRESPECT_INSTALL_PREFIX_CONFIG=ON`.

- Manpages (and their HTML representations) are generated from the `.ronn` source
files in the repository, using the [ronn](https://github.com/rtomayko/ronn) tool.
This does not happen automatically as part of the build process; to regenerate the
man pages you'll need to run `make manpages`. This target assumes that `ronn` is
in your PATH.

- Building with some versions of CMake may fail with `unable to find parser.h`.
If this happens, try updating CMake. If it still fails, don't clone ZMap into a
path that contains the string `.com`, and try again.

- ZMap may be installed to an alternative directory, with the `CMAKE_INSTALL_PREFIX`
option. For example, to install it in `$HOME/opt` run
    ```sh
    cmake -DCMAKE_INSTALL_PREFIX=$HOME/opt .
    make -j4
    make install
    ```
