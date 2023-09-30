<img width="150" height="150" align="left" style="float: left; margin: 0 10px 0 0;" alt="rz-ghidra logo" src="https://raw.githubusercontent.com/rizinorg/rz-ghidra/master/assets/logo.svg">

# rz-ghidra

<!--[![Build Status](https://travis-ci.com/rizinorg/rz-ghidra-dec.svg?token=JDmXp2pDhXxtPErySVHM&branch=master)](https://travis-ci.com/rizinorg/rz-ghidra)-->

This is an integration of the Ghidra decompiler and Sleigh Disassembler for [Rizin](https://github.com/rizinorg/rizin).
It is solely based on the decompiler part of Ghidra, which is written entirely in
C++, so Ghidra itself is not required at all and the plugin can be built self-contained.
This project was presented, initially for radare2, at r2con 2019 as part of the Cutter talk: [https://youtu.be/eHtMiezr7l8?t=950](https://youtu.be/eHtMiezr7l8?t=950)

## Usage

```
Usage: pdg   # Native Ghidra decompiler plugin
| pdg           # Decompile current function with the Ghidra decompiler
| pdgd          # Dump the debug XML Dump
| pdgx          # Dump the XML of the current decompiled function
| pdgj          # Dump the current decompiled function as JSON
| pdgo          # Decompile current function side by side with offsets
| pdgs          # Display loaded Sleigh Languages
| pdg*          # Decompiled code is returned to rizin as comment
```

The following config vars (for the `e` command) can be used to adjust rz-ghidra's behavior:

```
    ghidra.cmt.cpp: C++ comment style
 ghidra.cmt.indent: Comment indent
     ghidra.indent: Indent increment
       ghidra.lang: Custom Sleigh ID to override auto-detection (e.g. x86:LE:32:default)
    ghidra.linelen: Max line length
   ghidra.nl.brace: Newline before opening '{'
    ghidra.nl.else: Newline before else
 ghidra.sleighhome: SLEIGHHOME
```

Here, `ghidra.sleighhome` must point to a directory containing the `*.sla`, `*.lspec`, ... files for
the architectures that should supported by the decompiler. This is however set up automatically when using
the rz-pm package or installing as shown below.

## Building

First, make sure the submodule contained within this repository is fetched and up to date:

```
git submodule init
git submodule update
```

Then, the Rizin plugin can be built and installed as follows:

```
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=~/.local ..
make
make install
```

Here, set the `CMAKE_INSTALL_PREFIX` to a location where Rizin can load the plugin from.
The install step is necessary for the plugin to work because it includes installing the necessary Sleigh files.
If you are using Rizin from git, also set `CMAKE_PREFIX_PATH` to the Rizin installation directory.

To also build the Cutter plugin, you must have Cutter installed from source under some prefix,
which can be optionally specified with `-DCMAKE_PREFIX_PATH=<path>`, then pass `-DBUILD_CUTTER_PLUGIN=ON` to cmake
to enable the plugin:
```
/my/path/rz-ghidra> mkdir build && cd build
/my/path/rz-ghidra/build> cmake -DBUILD_CUTTER_PLUGIN=ON -DCMAKE_PREFIX_PATH=/path/to/cutter/prefix -DCMAKE_INSTALL_PREFIX=~/.local ..
/my/path/rz-ghidra/build> make && make install
```
By default, the Cutter plugin is installed in an automatically chosen path in the current user's home directory.
This path can be overriden with `-DCUTTER_INSTALL_PLUGDIR`.

## Versioning and Rizin Compatibility

Rizin has a quickly evolving C API so it is necessary to be explicit about which versions
of rz-ghidra are compatible with which versions of Rizin:

When using Rizin and rz-ghidra from git:
* rz-ghidra branch `dev` follows along Rizin branch `dev`.
* rz-ghidra branch `stable` follows along Rizin branch `stable`.

Regarding releases, rz-ghidra is generally released simultaneously with Rizin and
often uses the same version numbers (but not guaranteed, do not depend on these numbers!).
Also, along with every Rizin release a tag like `rz-0.1.2` is created on rz-ghidra, which exactly
points to an rz-ghidra release and indicates that this release is compatible with the specified Rizin version.
These tags can be used by distribution maintainers to look up how to set up dependencies.

## License

Please note that this plugin is available under the **LGPLv3**, which
is more strict than Ghidra's license!

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
