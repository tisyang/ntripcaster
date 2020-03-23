# ntripcaster
Ntrip broadcaster written in c and libev, support windows and linux.

For now, it can now transmit data between ntrip servers and ntrip clients, with source table and authorization support.

基于 libev 库实现的 C 语言版本 Ntripcaster 程序，支持 windows 和 linux。

目前可以支持 ntrip client 和 ntrip server 交换数据、动态源列表，以及密码验证（client 和 source 都支持）。

## Build 构建
Need cmake and git and libev.

Windows only test on MinGW/MinGW-w64 toolchains.

需要 cmake 和 git 工具，以及系统安装了 libev (仅linux下需要，Debian/Ubuntu 可以使用 `apt-get install libev-dev` 安装）。

Windows 编译仅在 MinGW/MinGW-w64 测试过。


```shell
git clone https://github.com/tisyang/ntripcaster.git
cd ntripcaster
git submodule update --init

mkdir build
cd build
cmake ..
make
```

## Pre-build binaries 预编译二进制文件
https://github.com/tisyang/ntripcaster_bin

## Usage 使用

程序使用 json 配置文件，默认配置文件名为 `ntripcaster.json` ，但可以通过命令行参数传入配置文件名: `ntripcaster.exe xxx.json`。

配置文件项说明：

+ `listen_addr`: 字符串，程序将使用的 caster 服务地址，默认为 "0.0.0.0".
+ `listen_port`: 整数，程序将使用的 caster 服务端口，默认为 2101.
+ `max_client`: 整数，可接入的 ntrip client 客户端最大数量，0表示无限制。默认为0.
+ `max_source`: 整数，可接入的 ntrip source 客户端最大数量，0表示无限制。默认为0.
+ `max_pending`: 整数，允许的无标识客户端（即非client也非source）最大数量，0表示无限制。默认为10.
+ `tokens_client`: object，每一项的名称表示一个 client 密码对，以冒号分隔的用户名和密码。值表示的可以访问的挂载点名称。挂载点支持 `*` 符号，表示可以访问任何挂载点。
+ `tokens_source`: object, 每一项的名称表示一个 source 密码。值表示可以写入数据的挂载点名称。挂载点支持 `*` 符号，表示可以访问任何挂载点。

配置文件示例:

```json
{
	"listen_addr":"0.0.0.0",
	"listen_port": 2101,
	"max_client": 0,
	"max_source": 0,
	"max_pending": 10,
	"tokens_client": {
		"test:test": "*"
	},
	"tokens_source": {
		"test": "*"
	}
}

```

## Contact Me 联系

lazy.tinker#outlook.com
