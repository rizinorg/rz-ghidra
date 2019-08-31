<img width="150" height="150" align="left" style="float: left; margin: 0 10px 0 0;" alt="r2ghidra-dec logo" src="https://raw.githubusercontent.com/thestr4ng3r/r2ghidra-dec/master/assets/logo.png">

# r2ghidra-dec

[![Build Status](https://travis-ci.com/thestr4ng3r/r2ghidra-dec.svg?token=JDmXp2pDhXxtPErySVHM&branch=master)](https://travis-ci.com/thestr4ng3r/r2ghidra-dec)

This is an integration of the Ghidra decompiler for [radare2](https://github.com/radare/radare2).
It is solely based on the decompiler part of Ghidra, which is written entirely in
C++, so Ghidra itself is not required at all and the plugin can be built self-contained.

## Installing

**TODO**: Info about r2pm

## Usage

**TODO**: Document commands and config vars

## Building

First, make sure the submodule contained within this repository is fetched and up to date:

```
git submodule init
git submodule update
```

Then, the plugin can be built as follows:

```
mkdir build && cd build
cmake ..
make
```

**TODO**: add install target and info about it

## License

Please note that this plugin is available under the **LGPLv3**, which
is more strict than Ghidra's license!

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
