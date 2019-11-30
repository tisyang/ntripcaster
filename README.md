# ntripcaster
Ntrip broadcaster written in c and libev.

For now, it can now transmit data between ntrip servers and ntrip clients, with source table and authorization support.

## Note
这是一个简易实现的 ntripcaster 服务器程序，也是一些其他基于 Ntrip 协议开发实现的程序的蓝本源码，包括千寻位置等 CORS 服务的差分分发代理程序（暂不开源）。后续将基于此仓库开发，逐步实现对于 Ntrip 各类功能程序的简化和抽象，使得不同场景可以基于简单的配置或编码，来实现期望的功能。

## Build
Need cmake and git and libev.

```shell
git clone https://github.com/lazytinker/ntripcaster.git
cd ntripcaster
git submodule update --init

mkdir build
cd build
cmake ..
make
```

## Pre-build binaries
https://github.com/lazytinker/ntripcaster_bin

## Usage

Run it, it will listen on port 2101.

## Contact Me

lazy.tinker#outlook.com
