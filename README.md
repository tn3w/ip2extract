# ip2extract

A high-performance Rust tool that extracts and categorizes proxy, VPN, and threat intelligence data from IP2Proxy LITE binary databases, outputting structured JSON lists.

## Features

- Parallel processing of IP2Proxy binary databases using Rayon
- Automatic categorization of IPs into 11 threat categories (Proxy, Mobile, Spam, etc.)
- Efficient memory-mapped file handling
- Outputs sorted, deduplicated lists in JSON format
- Automated updates via GitHub Actions

## Categories

Extracts data for: Public Proxy, Data Center, Commercial, Education, Government, ISP, Mobile, Spam, Scanner, Botnet, and Bogon IPs.

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
    "ip2proxy_vpn": {
      "addresses": [123456789, ...],
      "networks": [[123456789, 123456890], ...]
    },
    ...
  }
}
```

## Attribution

This project uses the [IP2Location LITE database](https://lite.ip2location.com) for IP geolocation and proxy detection.
