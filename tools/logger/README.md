# `logger` tool

> logs events to stdout

A peer-observer tool that logs all received event messages. By default, all events are shown.
This can be a lot. Events can be filtered by type. For example, `--messages` only shows P2P
messages. Using `--messages --connections` together shows P2P messages and connections

## Example

For example, connect to a NATS server on 128.0.0.1:1234 and only log connection events:

```
$ cargo run --bin logger -- --nats-address 127.0.0.1:1234 --connections

or

$ ./target/[release/debug]/logger -n 127.0.0.1:1234 --connections
```

The logger output looks similar to the following:

```
...
2025-06-26T12:52:08.364Z INFO  [logger] --> to id=11937171 (conn_type=1): wtxidrelay
2025-06-26T12:52:08.364Z INFO  [logger] --> to id=11937171 (conn_type=1): sendaddrv2
2025-06-26T12:52:08.364Z INFO  [logger] --> to id=11937171 (conn_type=1): verack
2025-06-26T12:52:08.411Z INFO  [logger] <-- from id=10237648 (conn_type=1): Inv([WTx(205bfe2dfbeb46c7d91963a13097ef49511ad2d71c3018fdbdebbff83d8caa2f), WTx(0cd27eb1f63d95c0ec82adf0090756aef0eb1b1e840634ec7a4f440919ab991c), WTx(98bb7eb29ab06dcfdd30aa4875ebafcedd14da2738d63d0cc8d6dcc0f3a12e8b), WTx(a361125873bffb5d70636e50bac18bd71963821d05ba07d9d70c91e660779632)])
2025-06-26T12:52:08.422Z INFO  [logger] <-- from id=10752006 (conn_type=1): AddrV2([Address(timestamp=1750941674, address=IPv4(XXX), port=8333, services=3077), Address(timestamp=1750941953, address=IPv4(XXX), port=8333, services=3081), Address(timestamp=1750941813, address=IPv6(XXX), port=8333, services=1032)])
2025-06-26T12:52:08.432Z INFO  [logger] <-- from id=10162242 (conn_type=1): Inv([WTx(5a7a949a920cf57eacd8ad38906a56ba6882188dda4ff9ea5660aad35adf1ef4), WTx(1acc1f2f3ec70c4ffd2181783bb2407e204be39b1017b5ae13d45b9b54a19e43), WTx(5a68c9197c31b5629c146be6d789a44bbb03e2c43633216ec0ca8cd73bd737f2), WTx(78ad4525de5b0e03db2b552b0091275caf781d57b04affc468d960ba645c1370)])
2025-06-26T12:52:08.437Z INFO  [logger] # CONN EvictedInboundConnection(conn=Connection(id=11937171, addr=<linkinglion>, conn_type=1, network=2), time_established=1750942328)
2025-06-26T12:52:08.437Z INFO  [logger] # CONN InboundConnection(conn=Connection(id=11937172, addr=<linkinglion>, conn_type=1, network=1), existing_connections=115)
2025-06-26T12:52:08.437Z INFO  [logger] # CONN ClosedConnection(conn=Connection(id=11937171, addr=<linkinglion>, conn_type=1, network=2), time_established=1750942328)
2025-06-26T12:52:08.447Z INFO  [logger] <-- from id=11554724 (conn_type=1): Inv([WTx(12eff03d987ef34ec759abe864bd88c2ecb4c994bd23ac18680fed251440020a), WTx(1e34d5e8d3e34ee7257363a34c877ea6031f0657574c78d6d1379485e1a8b533), WTx(68ae6c3279f1797f08f90948d7599ec60a476f896013f164a49b38eae10c6cf9), WTx(d1d6a9a50d1059db07a8367e52a6569d989f2dcdde24e56369aae2aaab4cf0aa), WTx(8c3c1033296b4c593560f40fd22929cbcc6f63c3ec20287829e9b52dea9a4ea2), WTx(77c7e46e402f94c4a03445479e727b67008e105f2c97d3120e8c2d2008b6c6c3)])
2025-06-26T12:52:08.457Z INFO  [logger] <-- from id=11875990 (conn_type=1): Pong(16368378148765531861)
2025-06-26T12:52:08.470Z INFO  [logger] <-- from id=8950578 (conn_type=1): Inv([WTx(12eff03d987ef34ec759abe864bd88c2ecb4c994bd23ac18680fed251440020a), WTx(1e34d5e8d3e34ee7257363a34c877ea6031f0657574c78d6d1379485e1a8b533), WTx(68ae6c3279f1797f08f90948d7599ec60a476f896013f164a49b38eae10c6cf9), WTx(8c3c1033296b4c593560f40fd22929cbcc6f63c3ec20287829e9b52dea9a4ea2), WTx(77c7e46e402f94c4a03445479e727b67008e105f2c97d3120e8c2d2008b6c6c3)])
2025-06-26T12:52:08.475Z INFO  [logger] <-- from id=11833825 (conn_type=1): Inv([WTx(5a7a949a920cf57eacd8ad38906a56ba6882188dda4ff9ea5660aad35adf1ef4), WTx(1acc1f2f3ec70c4ffd2181783bb2407e204be39b1017b5ae13d45b9b54a19e43), WTx(205bfe2dfbeb46c7d91963a13097ef49511ad2d71c3018fdbdebbff83d8caa2f), WTx(0cd27eb1f63d95c0ec82adf0090756aef0eb1b1e840634ec7a4f440919ab991c), WTx(a361125873bffb5d70636e50bac18bd71963821d05ba07d9d70c91e660779632), WTx(5de0156daa756bdcad84a93699972a6ecb451841f2404ad181bd540c87006756), WTx(f2c8df33b2ef2e15c6d239e05f651927b4108758d99bafb478e76b9f7827e19d)])
2025-06-26T12:52:08.475Z INFO  [logger] --> to id=8444252 (conn_type=2): Inv([WTx(1e34d5e8d3e34ee7257363a34c877ea6031f0657574c78d6d1379485e1a8b533), WTx(68ae6c3279f1797f08f90948d7599ec60a476f896013f164a49b38eae10c6cf9), WTx(8c3c1033296b4c593560f40fd22929cbcc6f63c3ec20287829e9b52dea9a4ea2), WTx(77c7e46e402f94c4a03445479e727b67008e105f2c97d3120e8c2d2008b6c6c3)])
2025-06-26T12:52:08.514Z INFO  [logger] <-- from id=11937172 (conn_type=1): Version(version=70016, services=3081, timestamp=1750942328, receiver=Address(timestamp=0, address=IPv4(XXX), port=8333, services=0), sender=Address(timestamp=0, address=IPv4(XXX), port=8333, services=0), nonce=0, user_agent=/bitcoinj:0.14.5/Bitcoin Wallet:5.40/, start_height=902650, relay=true)
2025-06-26T12:52:08.519Z INFO  [logger] --> to id=11937172 (conn_type=1): Version(version=70016, services=3080, timestamp=1750942328, receiver=Address(timestamp=0, address=IPv4(XXX), port=62311, services=0), sender=Address(timestamp=0, address=IPv4(0.0.0.0), port=0, services=3080), nonce=redacted, user_agent=/Satoshi:28.00.0/, start_height=902811, relay=true)
2025-06-26T12:52:08.519Z INFO  [logger] --> to id=11937172 (conn_type=1): wtxidrelay
2025-06-26T12:52:08.519Z INFO  [logger] --> to id=11937172 (conn_type=1): sendaddrv2
2025-06-26T12:52:08.519Z INFO  [logger] --> to id=11937172 (conn_type=1): verack
2025-06-26T12:52:08.593Z INFO  [logger] <-- from id=11937172 (conn_type=1): verack
2025-06-26T12:52:08.598Z INFO  [logger] --> to id=11937172 (conn_type=1): SendCompact(send_compact=false, version=2)
2025-06-26T12:52:08.598Z INFO  [logger] --> to id=11937172 (conn_type=1): Ping(2927426282439637971)
2025-06-26T12:52:08.598Z INFO  [logger] --> to id=11937172 (conn_type=1): GetHeaders(version=70016, locator_hashes=[0000000000000000000180924ed5328277133ac6f43bd8704094d948b39024be, 0000000000000000000064ab31451914de843cd2b2d249ee5c0b3dfc7336db4d, 00000000000000000001804c7b157f02fee8e267d717bd70451dcfdddde218cf, 000000000000000000019809e3aeb76ddbbaa2cbebe3cfd2d87f3b6e596c8acb, 0000000000000000000194405cf767c9b2e475457d76efa5d6e8da0cb2eea8dc, 00000000000000000000da88a2f892b5f5fec51b115750da35be02ab53b41a4e, 000000000000000000019bbaa678ee7f221e90ba86e163c75a0618eb2964dd8c, 00000000000000000000dbc6dea61e2ed9bc419a3d7487b489fcd04bfffbdb39, 000000000000000000018fa334ad00f30152a8a605a341bd3409b8b8ed941ad4, 000000000000000000000323353cc337f4aa26866f31be27e4c71b8c58199d1f, 00000000000000000001f8cf26868f2f945022a794edfcc99faf1a475797aef0, 00000000000000000000a75c8528e96162b7f85f08eac05ab8101e4503b60dff, 000000000000000000018a1f0c394689a5bca621721568d7a965a63c30e270b3, 000000000000000000007f3f4458f195baf4f1f98d619856d38476bb4c66af2d, 000000000000000000009264d6bc1688809d47bd157c822f2f1a9d14ddc0c234, 00000000000000000001ba8201808ae852669c8f9ec0d44e92731a669fba9a06, 000000000000000000015b05ba2c8fedf340f6d0dd195d1b54d18e311ddba2ad, 000000000000000000014b0e265bb393bf5e6f6f45a4f1358c547468081c9edc, 00000000000000000001b2ef2e1bd9172440004ce053711288dac57885a901aa, 00000000000000000001f394a82133377b7daa3b6166ce0e719320a1ddf5c115, 000000000000000000022ec1b664f873d7295d11c222891c90b74c59ac680553, 000000000000000000012346937de9addf8c7bef7d90a2c6781edab1c707e814, 000000000000000000008d4bb4b5f1059654a413f37403b6b5d7811ad2891f89, 000000000000000000006fb6980c1426057c513eb38748824c695dcfedeb57dc, 000000000000000000014b2a52ea7cce61c43ed74bf862edfb891f93a0bea06f, 000000000000000000019dfe6fa77843516296a87a30e53e6a065ddb88f96bea, 00000000000000000000397ebc584206cbf954039195c56fb71dada436f08f50, 0000000000000000000063d3f5914aeb2b8b3f1bd039d95092bbcf6ec3ba88da, 00000000000000000006780c877f04a17cf00f8698e4c039d871abee5e1d974d, 00000000000000000e21f42a8d23120ba15ce89398ae6333a61ab28920eab0c3, 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f], stop_hash=0000000000000000000000000000000000000000000000000000000000000000)
2025-06-26T12:52:08.598Z INFO  [logger] --> to id=11937172 (conn_type=1): FeeFilter(1000)
..
```



## Usage

```
A peer-observer tool that logs all received event messages. By default, all events are shown. This can be a lot. Events can be filtered by type. For example, `--messages` only shows P2P messages. Using `--messages --connections` together shows P2P messages and connections

Usage: logger [OPTIONS]

Options:
  -a, --nats-address <ADDRESS>
          The NATS server address the extractor/tool should connect and subscribe to [default: 127.0.0.1:4222]
  -u, --nats-username <USERNAME>
          The NATS username the extractor/tool should try to authentificate to the NATS server with
  -p, --nats-password <PASSWORD>
          The NATS password the extractor/tool should try to authentificate to the NATS server with
  -f, --nats-password-file <PASSWORD_FILE>
          A path to a file containing a password the extractor/tool should try to authentificate to the NATS server with
  -l, --log-level <LOG_LEVEL>
          The log level the tool should run on. Events are logged with the INFO log level. Valid log levels are "trace", "debug", "info", "warn", "error". See https://docs.rs/log/latest/log/enum.Level.html [default: DEBUG]
      --messages
          If passed, show P2P message events
      --connections
          If passed, show P2P connection events
      --mempool
          If passed, show mempool events
      --validation
          If passed, show validation events
      --rpc
          If passed, show RPC events
      --ipc
          If passed, show IPC events
      --p2p-extractor
          If passed, show p2p-extractor events
      --log-extractor
          If passed, show log-extractor events
  -h, --help
          Print help
  -V, --version
          Print version
```
