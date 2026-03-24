# `rpc` extractor

> publishes data fetched from RPC

A peer-observer extractor that periodically queries the Bitcoin Core RPC interfaces and publishes the results as events into a NATS pub-sub queue.

## Example

For example, connect to a NATS server on 128.0.0.1:1234 and query events every 20 seconds using the RPC user `peer-observer` with the password `hunter2`:

```
$ cargo run --bin rpc-extractor -- --rpc-user peer-observer --rpc-password hunter2 --nats-address 128.0.0.1:1234 --query-interval 20
```

While setting up a dedicated user and password authentification for it is recommended, a cookie file can be used with `--rpc-cookie-file`.

## Usage

```
$ cargo run --bin rpc-extractor -- --help
The peer-observer rpc-extractor periodically queries data from the Bitcoin Core RPC endpoint and publishes the results as events into a NATS pub-sub queue

Usage: rpc-extractor [OPTIONS] <--rpc-cookie-file <RPC_COOKIE_FILE>|--rpc-user <RPC_USER>>

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
          The log level the extractor should run with. Valid log levels are "trace", "debug", "info", "warn", "error". See https://docs.rs/log/latest/log/enum.Level.html [default: DEBUG]
      --rpc-host <RPC_HOST>
          Address of the Bitcoin Core RPC endpoint the RPC extractor will query [default: 127.0.0.1:8332]
      --rpc-user <RPC_USER>
          RPC username for authentication with the Bitcoin Core RPC endpoint
      --rpc-password <RPC_PASSWORD>
          RPC password for authentication with the Bitcoin Core RPC endpoint
      --rpc-cookie-file <RPC_COOKIE_FILE>
          An RPC cookie file for authentication with the Bitcoin Core RPC endpoint
      --query-interval <QUERY_INTERVAL>
          Interval (in seconds) in which to query from the Bitcoin Core RPC endpoint [default: 10]
      --query-interval-less-frequent <QUERY_INTERVAL_LESS_FREQUENT>
          Interval (in seconds) in which to query resource-intensive or less frequently changing RPCs from the Bitcoin Core RPC endpoint. These currently include: - getchaintxstats (infrequent changes) - getblockchaininfo (infrequent changes) - getrawaddrman (resource intensive) [default: 120]
      --prometheus-address <PROMETHEUS_ADDRESS>
          Address to serve Prometheus metrics on [default: 127.0.0.1:8284]
      --disable-getpeerinfo
          Disable querying and publishing of `getpeerinfo` data
      --disable-getmempoolinfo
          Disable querying and publishing of `getmempoolinfo` data
      --disable-uptime
          Disable querying and publishing of `uptime` data
      --disable-getnettotals
          Disable querying and publishing of `getnettotals` data
      --disable-getmemoryinfo
          Disable querying and publishing of `getmemoryinfo` data
      --disable-getaddrmaninfo
          Disable querying and publishing of `getaddrmaninfo` data
      --disable-getchaintxstats
          Disable querying and publishing of `getchaintxstats` data
      --disable-getnetworkinfo
          Disable querying and publishing of `getnetworkinfo` data
      --disable-getblockchaininfo
          Disable querying and publishing of `getblockchaininfo` data
      --disable-getorphantxs
          Disable querying and publishing of `getorphantxs` data
      --disable-getrawaddrman
          Disable querying and publishing of `getrawaddrman` data
  -h, --help
          Print help
  -V, --version
          Print version
```

## Supported RPCs

The `rpc` extractor currently supports the following Bitcoin Core RPC methods.

high polling frequency: interval controlled with `--query-interval`
low polling frequency: interval controlled with `--query-interval-less-frequent`

| method | polling frequency | description |
| --- | --- | --- |
| [`getpeerinfo`](https://developer.bitcoin.org/reference/rpc/getpeerinfo.html) | high | Returns data about each connected node. |
| [`getmempoolinfo`](https://developer.bitcoin.org/reference/rpc/getmempoolinfo.html) | high | Returns details on the active state of the TX memory pool. |
| [`uptime`](https://developer.bitcoin.org/reference/rpc/uptime.html) | high | Returns the total uptime of the server. |
| [`getnettotals`](https://developer.bitcoin.org/reference/rpc/getnettotals.html) | high | Returns information about network traffic, including bytes in, bytes out, and current time. |
| [`getmemoryinfo`](https://developer.bitcoin.org/reference/rpc/getmemoryinfo.html) | high | Returns information about memory usage. |
| [`getaddrmaninfo`](https://github.com/bitcoin/bitcoin/pull/27511) | high | Returns the number of addresses in the `new` and `tried` tables and their sum for all networks. |
| [`getchaintxstats`](https://developer.bitcoin.org/reference/rpc/getchaintxstats.html) | low | Compute statistics about the total number and rate of transactions in the chain. |
| [`getnetworkinfo`](https://developer.bitcoin.org/reference/rpc/getnetworkinfo.html) | high | Returns various state info regarding P2P networking. |
| [`getblockchaininfo`](https://developer.bitcoin.org/reference/rpc/getblockchaininfo.html) | low | Returns various state info regarding blockchain processing. |
| [`getorphantxs`](https://github.com/bitcoin/bitcoin/pull/30793) | high | (EXPERIMENTAL) Shows transactions in the tx orphanage. |
| [`getrawaddrman`](https://github.com/bitcoin/bitcoin/pull/28523) | low | (EXPERIMENTAL) Returns information on all address manager entries for the new and tried tables. |
