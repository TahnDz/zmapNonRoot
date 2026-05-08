# ZMap Non-Root

`zmapNonRoot` is a fork of [ZMap](https://github.com/zmap/zmap) focused on one practical goal: make ZMap usable in environments where you do not have `root`, do not want to rely on `apt`, or are working inside Termux.

It keeps the upstream ZMap architecture and build system, then layers on:

- an unprivileged runtime path for supported probe modules on Linux and Android/Termux
- a one-step local build flow for user-owned prefixes
- better Termux defaults so installed packages are discovered automatically

## What This Fork Is Good At

- Building and installing ZMap without `sudo`.
- Running supported scan modules when raw sockets are unavailable.
- Working cleanly in user-space environments such as Termux.
- Preserving the familiar ZMap CLI, output modules, sharding, filters, and rate controls where the unprivileged backend applies.

This fork is for legitimate testing, research, and inventory work in networks you own or are explicitly authorized to assess.

## Quick Start

If your dependencies are already installed under a user-owned prefix, the fastest path is:

```sh
sh scripts/setup-local.sh
```

That wrapper will:

- resolve sensible local paths
- validate the toolchain and libraries
- configure the build
- compile the binaries
- install into a user-local prefix

On Termux, it automatically uses `$PREFIX` as the dependency prefix, so you usually do not need extra environment variables.

To inspect what paths the wrapper will use before building:

```sh
sh scripts/setup-local.sh env
```

For more installation detail, see [INSTALL.md](INSTALL.md).

## Non-Root Runtime

On Linux systems without `root` or `CAP_NET_RAW`, ZMap can fall back to an unprivileged backend for compatible probe modules. You can request it explicitly with:

```sh
zmap --unprivileged -p 80 192.0.2.0/24
```

The unprivileged backend currently supports:

- `tcp_synscan`
- UDP-based modules that work over ordinary datagram sockets, including `udp`, `dns`, `ntp`, `upnp`, and `bacnet`

What it keeps:

- target iteration
- sharding
- filters
- output modules
- rate controls

What it does not replace:

- raw packet injection semantics
- passive `libpcap` capture behavior
- modules that depend on custom Ethernet or IP packet construction

If you need the original privileged behavior, use the normal root-capable backend.

## Build Flow

The new single-entry script is:

```sh
sh scripts/setup-local.sh
```

It also supports subcommands:

```sh
sh scripts/setup-local.sh env
sh scripts/setup-local.sh check
sh scripts/setup-local.sh build
sh scripts/setup-local.sh install
```

The older phase-specific scripts are still available:

```sh
sh scripts/bootstrap-env.sh
sh scripts/build.sh
sh scripts/install-local.sh
```

Default paths:

- `ZMAP_DEPS_PREFIX`: `$PREFIX` on Termux, otherwise `$HOME/.local`
- `ZMAP_BUILD_DIR`: `$HOME/build-zmap`
- `ZMAP_INSTALL_PREFIX`: `$HOME/.local/zmap`

Example overrides:

```sh
ZMAP_DEPS_PREFIX=$HOME/.local \
ZMAP_BUILD_DIR=$HOME/build-zmap \
ZMAP_INSTALL_PREFIX=$HOME/.local/zmap \
sh scripts/setup-local.sh build
```

## Dependencies

This fork does not remove ZMap's core build dependencies. You still need working installs of:

- `cc`
- `cmake`
- `pkg-config`
- `flex`
- `byacc`
- `gengetopt`
- `gmp`
- `libpcap`
- `json-c`
- `libunistring`
- `Judy`

The helper scripts validate these before building and print the active prefixes if something is missing.

## Notes for Termux

- The local setup wrapper detects Termux automatically.
- Dependency discovery defaults to `$PREFIX`.
- Install output defaults to `$HOME/.local/zmap`.
- The unprivileged backend is intended for exactly this kind of environment, but module support is still narrower than the privileged path.

## Documentation

- [INSTALL.md](INSTALL.md): installation and dependency details
- [10gigE.md](10gigE.md): notes for high-speed upstream ZMap deployments
- [README.netmap.md](README.netmap.md): netmap-specific information
- [examples/udp-probes/README](examples/udp-probes/README): UDP probe examples
- [CHANGELOG.md](CHANGELOG.md): project change history

## Upstream Context

ZMap is a fast stateless network scanner originally built for large-scale measurement. On standard privileged deployments it can scan very large IPv4 target sets quickly, and upstream also supports acceleration paths such as netmap and PF_RING for specialized environments.

If you need application-layer follow-up work such as banners or TLS handshakes, look at [ZGrab2](https://github.com/zmap/zgrab2).

## Responsible Use

Network scanning has operational and ethical consequences. Use the tool only against systems and networks you are authorized to assess. Prefer the smallest target scope and lowest rate that accomplish your task, and provide a clear opt-out path when appropriate.

## Citation

If you use ZMap in research, cite the original paper:

```text
@inproceedings{durumeric2013zmap,
  title={{ZMap}: Fast Internet-wide scanning and its security applications},
  author={Durumeric, Zakir and Wustrow, Eric and Halderman, J Alex},
  booktitle={22nd USENIX Security Symposium},
  year={2013}
}
```

## License

ZMap Copyright 2024 Regents of the University of Michigan.

This repository remains under the Apache License, Version 2.0. See [LICENSE](LICENSE).
