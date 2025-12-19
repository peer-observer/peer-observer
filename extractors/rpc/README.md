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
  -n, --nats-address <NATS_ADDRESS>
          Address of the NATS server where the extractor will publish messages to [default: 127.0.0.1:4222]
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
  -h, --help
          Print help
  -V, --version
          Print version
```
