<!--<img width="150" height="150" align="left" style="float: left; margin: 0 10px 0 0;" alt="rz-ghidra-dec logo" src="https://raw.githubusercontent.com/radareorg/rz-ghidra-dec/master/assets/logo.png">-->

# rz-ghidra

<!--[![Build Status](https://travis-ci.com/radareorg/rz-ghidra-dec.svg?token=JDmXp2pDhXxtPErySVHM&branch=master)](https://travis-ci.com/rizinorg/rz-ghidra)-->

This is an integration of the Ghidra decompiler and Sleigh Disassembler for [rizin](https://github.com/rizinorg/rizin).
It is solely based on the decompiler part of Ghidra, which is written entirely in
C++, so Ghidra itself is not required at all and the plugin can be built self-contained.
This project was presented, initially for rizin, at r2con 2019 as part of the Cutter talk: [https://youtu.be/eHtMiezr7l8?t=950](https://youtu.be/eHtMiezr7l8?t=950)

## Installing

An rz-pm package is available that can easily be installed like:
```
rz-pm -i rz-ghidra
```

This package only installs the rizin part.
To use rz-ghidra from cutter, either use a provided pre-built release starting with
Cutter 1.9, which bundles rz-ghidra, or follow the build instructions below.

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

Then, the rizin plugin can be built and installed as follows:

```
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=~/.local ..
make
make install
```

Here, set the `CMAKE_INSTALL_PREFIX` to a location where rizin can load the plugin from.
The install step is necessary for the plugin to work because it includes installing the necessary Sleigh files.

To also build the Cutter plugin, pass `-DBUILD_CUTTER_PLUGIN=ON -DCUTTER_SOURCE_DIR=/path/to/cutter/source` to cmake, for example like this:
```
/my/path> git clone https://github.com/rizinorg/cutter
/my/path> # build Cutter, clone rz-ghidra, etc.
...
/my/path/rz-ghidra> mkdir build && cd build
/my/path/rz-ghidra/build> cmake -DBUILD_CUTTER_PLUGIN=ON -DCUTTER_SOURCE_DIR=/my/path/cutter -DCMAKE_INSTALL_PREFIX=~/.local ..
/my/path/rz-ghidra/build> make && make install
```

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
