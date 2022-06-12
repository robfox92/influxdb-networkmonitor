# influxdb-networkmonitor

This is a tool to collect traffic data on your network and store it in influxdb.  It stores the IP address, hostname, ethernet/MAC address and {sent, received} bytes/sec of a given network device. Hostname lookup is provided by via `gethostbyaddr()`, and is cached for 10 minutes.

Traffic data is collected by starting a tcpdump session on a remote network device (e.g. a router) over ssh, and processing the files with [pyshark](https://github.com/KimiNewt/pyshark/). Traffic data to/from the collection machine is excluded. Data for hosts outside the specified subnet is not collected.

## Installation

Clone this repository:

`git clone https://github.com/robfox92/influxdb-networkmonitor.git`

Install requirements:

`pip install -r requirements.txt`

## Usage

### Basic usage

`./influxdb-networkmonitor.py --influxdb_token=YOUR_INFLUXDB_TOKEN --influxdb_org=YOUR_INFLUXDB_ORG --influxdb_bucket=YOUR_INFLUXDB_BUCKET`

### Typical usage

`./influxdb-networkmonitor.py --influxdb_url=http://YOUR_INFLUX_HOST --influxdb_token=YOUR_INFLUXDB_TOKEN --influxdb_org=YOUR_INFLUXDB_ORG --influxdb_bucket=YOUR_INFLUXDB_BUCKET`

### All options

#### Influxdb-related

```
    --influxdb_url         address of influxdb instance (default: http://localhost:8086)
    --influxdb_token       token for accessing influxdb
    --influxdb_org         influxdb organisation to write to
    --influxdb_bucket      influxdb bucket to write to
    --send_interval        seconds to wait between sending to influxdb (default: 5)
```

#### Router-related

```
--router_address       address of router to collect traffic data from (default:10.0.0.1)
--router_port          port the router accepts ssh connections on (default:22)
--traffic_subnet       subnet to collect traffic data from (default: 10.0.0.0/8)
```

## Useful notes

* [MAC Address Lookup](https://macaddress.io/mac-address-lookup)

## License

This project is licensed under the GPLv3 license.