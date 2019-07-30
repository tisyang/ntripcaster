# ntripcaster
Ntrip broadcaster written in c and libev.

For now, it can now transmit data between ntrip servers and ntrip clients, with source table and authorization support.

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

## Usage

Run it, it will listen on port 2101.

