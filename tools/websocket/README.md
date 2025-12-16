# `websocket` tool

> publishes events into a websocket as JSON

A peer-observer tool that sends out all events on a websocket. Can be used to
visualize the events in the browser. The `www/*.html` files implement a few
visualizations.

## Example

For example, connect to a NATS server on 128.0.0.1:1234 and start the websocket server on 127.0.0.1:4848:

```
$ cargo run --bin websocket -- --nats-address 127.0.0.1:1234 --websocket-address 127.0.0.1:4848

or

$ ./target/[release/debug]/websocket -n 127.0.0.1:1234 --websocket-address 127.0.0.1:4848
```

## Usage

```
$ cargo run --bin websocket -- --help
A peer-observer tool that sends out all events on a websocket

Usage: websocket [OPTIONS]

Options:
  -n, --nats-address <NATS_ADDRESS>
          The NATS server address the tool should connect and subscribe to [default: 127.0.0.1:4222]
  -w, --websocket-address <WEBSOCKET_ADDRESS>
          The websocket address the tool listens on [default: 127.0.0.1:47482]
  -l, --log-level <LOG_LEVEL>
          The log level the took should run with. Valid log levels are "trace", "debug", "info", "warn", "error". See https://docs.rs/log/latest/log/enum.Level.html [default: DEBUG]
  -h, --help
          Print help
  -V, --version
          Print version
```

## Websocket Picker

The HTML visualization pages (`www/*.html`) include a websocket picker that allows users to connect to and switch between multiple websocket endpoints from a single page. This is useful when running multiple `websocket` tool instances (e.g., monitoring different Bitcoin nodes).

### How it works

Each HTML page includes:
- An empty `<div>` element with the id `websocket-picker` where the picker UI is rendered
- The `js/websocket-picker.js` script that provides the picker functionality
- A call to `initWebsocketPicker()` on page load that fetches and displays available websockets

### `websockets.json` file format

The websocket picker loads a JSON file named `websockets.json` that maps friendly names to websocket URLs. This file must be served alongside your HTML files at the same path.

**Format:**
```json
{
  "name1": "ws://host:port",
  "name2": "wss://host:port/path",
  "name3": "/websocket/relative/path"
}
```

Each key is a display name shown in the picker UI, and each value is the websocket URL (can be absolute URLs with `ws://` or `wss://`, or relative paths).

### Examples

**Development setup:**

Create a `websockets.json` file in your `www/` directory:

```json
{
  "dev": "ws://127.0.0.1:47482"
}
```

**Production setup with nginx:**

If you're serving the HTML files behind nginx with TLS termination, you can serve the JSON file as a static file or use an nginx location block:

```nginx
location /websockets.json {
    add_header Content-Type application/json;
    add_header Access-Control-Allow-Origin *;
    return 200 '{ "prod": "wss://mycustompeer.observer/websocket" }';
}
```

**Multiple nodes:**

```json
{
  "alice": "/websocket/alice/",
  "bob": "/websocket/bob/",
  "charlie": "/websocket/charlie/"
}
```

### Serving the file

The `websockets.json` file must be accessible at the same URL path as your HTML files. For example:
- If your HTML files are served at `https://example.com/www/peers.html`
- The JSON file should be accessible at `https://example.com/www/websockets.json`

You can serve it as:
- A static file alongside your HTML files
- A dynamically generated endpoint (e.g., via nginx `return` directive or a backend service)
- Any HTTP-accessible location that returns valid JSON