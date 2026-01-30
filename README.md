# ip2extract

A high-performance Rust tool that extracts and categorizes proxy, VPN, and threat intelligence data from IP2Proxy LITE binary databases, outputting structured JSON lists.

## Features

- Parallel processing of IP2Proxy binary databases using Rayon
- Automatic categorization of IPs into 11 threat categories (Proxy, Mobile, Spam, etc.)
- Efficient memory-mapped file handling
- Outputs sorted, deduplicated lists in JSON format
- Automated updates via GitHub Actions

## Categories

Extracts data for: `ip2proxy_pub` (Public Proxy), `ip2proxy_dch` (Data Center), `ip2proxy_com` (Commercial), `ip2proxy_edu` (Education), `ip2proxy_gov` (Government), `ip2proxy_isp` (ISP), `ip2proxy_mob` (Mobile), `ip2proxy_spam` (Spam), `ip2proxy_scanner` (Scanner), `ip2proxy_botnet` (Botnet), and `ip2proxy_bogon` (Bogon).

## Usage

```bash
cargo build --release
cargo run --release
```

Requires `IP2PROXY-LITE-PX10.BIN` database file in the working directory.

## Output

Generates `lists.json` with timestamp and categorized IP addresses/ranges:

```json
{
  "timestamp": 1234567890,
  "lists": {
    "ip2proxy_pub": {
      "addresses": [123456789, ...],
      "networks": [[123456789, 123456890], ...]
    },
    ...
  }
}
```

## Attribution

This project uses the [IP2Location LITE database](https://lite.ip2location.com) for IP geolocation and proxy detection.
