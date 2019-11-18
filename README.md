<img width="150" height="150" align="left" style="float: left; margin: 0 10px 0 0;" alt="r2ghidra-dec logo" src="https://raw.githubusercontent.com/radareorg/r2ghidra-dec/master/assets/logo.png">

# r2ghidra-dec

[![Build Status](https://travis-ci.com/radareorg/r2ghidra-dec.svg?token=JDmXp2pDhXxtPErySVHM&branch=master)](https://travis-ci.com/radareorg/r2ghidra-dec)

This is an integration of the Ghidra decompiler for [radare2](https://github.com/radareorg/radare2).
It is solely based on the decompiler part of Ghidra, which is written entirely in
C++, so Ghidra itself is not required at all and the plugin can be built self-contained.
This project was presented at r2con 2019 as part of the Cutter talk: [https://youtu.be/eHtMiezr7l8?t=950](https://youtu.be/eHtMiezr7l8?t=950)

## Installing

An r2pm package is available that can easily be installed like:
```
r2pm -i r2ghidra-dec
```

This package only installs the radare2 part.
To use r2ghidra from cutter, either use a provided pre-built release starting with
Cutter 1.9, which bundles r2ghidra, or follow the build instructions below.

## Usage

```
Usage: pdg   # Native Ghidra decompiler plugin
| pdg           # Decompile current function with the Ghidra decompiler
| pdgd          # Dump the debug XML Dump
| pdgx          # Dump the XML of the current decompiled function
| pdgj          # Dump the current decompiled function as JSON
| pdgo          # Decompile current function side by side with offsets
| pdgs          # Display loaded Sleigh Languages
| pdg*          # Decompiled code is returned to r2 as comment
```

The following config vars (for the `e` command) can be used to adjust r2ghidra's behavior:

```
    r2ghidra.cmt.cpp: C++ comment style
 r2ghidra.cmt.indent: Comment indent
     r2ghidra.indent: Indent increment
       r2ghidra.lang: Custom Sleigh ID to override auto-detection (e.g. x86:LE:32:default)
    r2ghidra.linelen: Max line length
   r2ghidra.nl.brace: Newline before opening '{'
    r2ghidra.nl.else: Newline before else
 r2ghidra.sleighhome: SLEIGHHOME
```

Here, `r2ghidra.sleighhome` must point to a directory containing the `*.sla`, `*.lspec`, ... files for
the architectures that should supported by the decompiler. This is however set up automatically when using
the r2pm package or installing as shown below.

## Building

First, make sure the submodule contained within this repository is fetched and up to date:

```
git submodule init
git submodule update
```

Then, the radare2 plugin can be built and installed as follows:

```
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=~/.local ..
make
make install
```

Here, set the `CMAKE_INSTALL_PREFIX` to a location where radare2 can load the plugin from.
The install step is necessary for the plugin to work because it includes installing the necessary Sleigh files.

To also build the Cutter plugin, pass `-DBUILD_CUTTER_PLUGIN=ON -DCUTTER_SOURCE_DIR=/path/to/cutter/source` to cmake, for example like this:
```
/my/path> git clone https://github.com/radareorg/cutter
/my/path> # build Cutter, clone r2ghidra-dec, etc.
...
/my/path/r2ghidra-dec> mkdir build && cd build
/my/path/r2ghidra-dec/build> cmake -DBUILD_CUTTER_PLUGIN=ON -DCUTTER_SOURCE_DIR=/my/path/cutter -DCMAKE_INSTALL_PREFIX=~/.local ..
/my/path/r2ghidra-dec/build> make && make install
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
