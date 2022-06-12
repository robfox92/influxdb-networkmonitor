# influxdb-networkmonitor

This is a tool to collect traffic data on your network and store it in influxdb.  It stores the IP address, hostname, ethernet/MAC address and {sent, received} bytes/sec of a given network device. Hostname lookup is provided by via `gethostbyaddr()`, and is cached for 10 minutes.

## Installation

Clone this repository:

`git clone https://github.com/robfox92/influxdb-networkmonitor.git`

Install requirements:

`pip install -r requirements.txt`

## Usage

Basic usage:

`./influxdb-networkmonitor.py --influxdb_token=YOUR_INFLUXDB_TOKEN --influxdb_org=YOUR_INFLUXDB_ORG --influxdb_bucket=YOUR_INFLUXDB_BUCKET`

## Useful notes

* [MAC Address Lookup](https://macaddress.io/mac-address-lookup)
