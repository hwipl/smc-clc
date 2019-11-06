# smc-clc

smc-clc is a command line tool for capturing SMC CLC traffic from a network
interface and parsing the SMC CLC handshake messages. The CLC handshake is part
of the [SMC protocol](https://www.rfc-editor.org/info/rfc7609) and is used to
establish SMC connections between communication partners.

## Installation

You can download and install smc-clc with its dependencies to your GOPATH or
GOBIN with the go tool:

```console
$ go get https://github.com/hwipl/smc-clc
```

## Usage

You can run smc-clc with the `smc-clc` command. Make sure your user has the
permission to capture traffic on the network interface.

You can specify the network interface with the option `-i`. For example, you
can specify the loopback interface with:

```console
$ smc-clc -i lo
```

Options of the `smc-clc` command:

```
  -dumps
        print message hex dumps
  -i string
        the interface to listen on (default "eth0")
  -promisc
        promiscuous mode (default true)
  -reserved
        print reserved values in messages
  -snaplen int
        pcap snaplen (default 2048)
  -timestamps
        print timestamps (default true)
```

## Examples

Regular output of a SMC handshake over IPv4 on the loopback interface:

```console
$ sudo ./smc-clc -i lo
Starting to listen on interface lo.
16:17:14.341225 127.0.0.1:60294 -> 127.0.0.1:50000: Proposal: Eyecatcher: SMC-R,
Type: 1 (Proposal), Length: 52, Version: 1, Flag: 0, Path: SMC-R,
Peer ID: 45472@98:03:9b:ab:cd:ef, SMC-R GID: fe80::9a03:9bff:feab:cdef,
RoCE MAC: 98:03:9b:ab:cd:ef, IP Area Offset: 0, SMC-D GID: 0,
IPv4 Prefix: 127.0.0.0/8, IPv6 Prefix Count: 0, Trailer: SMC-R
16:17:14.342858 127.0.0.1:50000 -> 127.0.0.1:60294: Accept: Eyecatcher: SMC-R,
Type: 2 (Accept), Length: 68, Version: 1, First Contact: 1, Path: SMC-R,
Peer ID: 45472@98:03:9b:ab:cd:ef, SMC-R GID: fe80::9a03:9bff:feab:cdef,
RoCE MAC: 98:03:9b:ab:cd:ef, QP Number: 228, RMB RKey: 5501, RMBE Index: 1,
RMBE Alert Token: 5, RMBE Size: 2 (65536), QP MTU: 3 (1024),
RMB Virtual Address: 0xf0a60000, Packet Sequence Number: 7534078,
Trailer: SMC-R
16:17:14.343078 127.0.0.1:60294 -> 127.0.0.1:50000: Confirm: Eyecatcher: SMC-R,
Type: 3 (Confirm), Length: 68, Version: 1, Flag: 0, Path: SMC-R,
Peer ID: 45472@98:03:9b:ab:cd:ef, SMC-R GID: fe80::9a03:9bff:feab:cdef,
RoCE MAC: 98:03:9b:ab:cd:ef, QP Number: 229, RMB RKey: 6271, RMBE Index: 1,
RMBE Alert Token: 6, RMBE Size: 2 (65536), QP MTU: 3 (1024),
RMB Virtual Address: 0xf0a40000, Packet Sequence Number: 887204,
Trailer: SMC-R
```

The output of the same SMC handshake with enabled hex dumps of the messages:

```console
$ sudo ./smc-clc -i lo -dumps
Starting to listen on interface lo.
16:17:14.341225 127.0.0.1:60294 -> 127.0.0.1:50000: Proposal: Eyecatcher: SMC-R,
Type: 1 (Proposal), Length: 52, Version: 1, Flag: 0, Path: SMC-R,
Peer ID: 45472@98:03:9b:ab:cd:ef, SMC-R GID: fe80::9a03:9bff:feab:cdef,
RoCE MAC: 98:03:9b:ab:cd:ef, IP Area Offset: 0, SMC-D GID: 0,
IPv4 Prefix: 127.0.0.0/8, IPv6 Prefix Count: 0, Trailer: SMC-R
00000000  e2 d4 c3 d9 01 00 34 10  b1 a0 98 03 9b ab cd ef  |......4.........|
00000010  fe 80 00 00 00 00 00 00  9a 03 9b ff fe ab cd ef  |................|
00000020  98 03 9b ab cd ef 00 00  7f 00 00 00 08 00 00 00  |................|
00000030  e2 d4 c3 d9                                       |....|
16:17:14.342858 127.0.0.1:50000 -> 127.0.0.1:60294: Accept: Eyecatcher: SMC-R,
Type: 2 (Accept), Length: 68, Version: 1, First Contact: 1, Path: SMC-R,
Peer ID: 45472@98:03:9b:ab:cd:ef, SMC-R GID: fe80::9a03:9bff:feab:cdef,
RoCE MAC: 98:03:9b:ab:cd:ef, QP Number: 228, RMB RKey: 5501, RMBE Index: 1,
RMBE Alert Token: 5, RMBE Size: 2 (65536), QP MTU: 3 (1024),
RMB Virtual Address: 0xf0a60000, Packet Sequence Number: 7534078,
Trailer: SMC-R
00000000  e2 d4 c3 d9 02 00 44 18  b1 a0 98 03 9b ab cd ef  |......D.........|
00000010  fe 80 00 00 00 00 00 00  9a 03 9b ff fe ab cd ef  |................|
00000020  98 03 9b ab cd ef 00 00  e4 00 00 15 7d 01 00 00  |............}...|
00000030  00 05 23 00 00 00 00 00  f0 a6 00 00 00 72 f5 fe  |..#..........r..|
00000040  e2 d4 c3 d9                                       |....|
16:17:14.343078 127.0.0.1:60294 -> 127.0.0.1:50000: Confirm: Eyecatcher: SMC-R,
Type: 3 (Confirm), Length: 68, Version: 1, Flag: 0, Path: SMC-R,
Peer ID: 45472@98:03:9b:ab:cd:ef, SMC-R GID: fe80::9a03:9bff:feab:cdef,
RoCE MAC: 98:03:9b:ab:cd:ef, QP Number: 229, RMB RKey: 6271, RMBE Index: 1,
RMBE Alert Token: 6, RMBE Size: 2 (65536), QP MTU: 3 (1024),
RMB Virtual Address: 0xf0a40000, Packet Sequence Number: 887204,
Trailer: SMC-R
00000000  e2 d4 c3 d9 03 00 44 10  b1 a0 98 03 9b ab cd ef  |......D.........|
00000010  fe 80 00 00 00 00 00 00  9a 03 9b ff fe ab cd ef  |................|
00000020  98 03 9b ab cd ef 00 00  e5 00 00 18 7f 01 00 00  |................|
00000030  00 06 23 00 00 00 00 00  f0 a4 00 00 00 0d 89 a4  |..#.............|
00000040  e2 d4 c3 d9                                       |....|
```
