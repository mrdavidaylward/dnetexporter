# dnetexporter
### Network Data Usage Exporter:

The dnetexporter is a Go application designed to capture network packets, analyze traffic between specified IP pairs, and export traffic metrics to Prometheus. This tool is invaluable for real-time monitoring of network activities, focusing on targeted IP pairs configurable through a JSON file. It leverages pcap for packet capturing and provides detailed insights into traffic patterns, aiding in network usage analysis.

# Features
Dynamic Configuration: Easily specify the network device and IP pairs for monitoring through a JSON configuration file.
Packet Capturing: Utilizes pcap to capture packets, with support for both IP addresses and subnets.
Prometheus Integration: Exports bytes and packets counts, segmented by source, destination, and direction, to Prometheus for comprehensive monitoring.
Activity Tracking: Tracks activity per IP pair, enabling the identification of inactive pairs for cleanup.
# Getting Started
## Prerequisites
Go (version 1.15 or later recommended)
libpcap installed on your system
A Prometheus server setup for metrics collection
Installation
Clone the repository to your local machine:

```
git clone https://github.com/yourusername/network-packet-observer.git
cd network-packet-observer
```
Build the application:

```
go build
```
Configuration
Create a config.json file in the root directory with the following structure:

```
{
    "device": "eth0",
    "ipPairs": [
        {
            "source": "192.168.1.1",
            "destination": "192.168.2.1"
        }
    ]
}
```
Running
Execute the binary with the required permissions to capture packets:

```
sudo ./network-packet-observer
The metrics are now being served on :9914/metrics.
```
Usage
The application is primarily intended for network administrators and developers needing to monitor specific IP pairs within their network. Once running, it captures packets matching the configured IP pairs and exports metrics to Prometheus.

### This Readme was mostly written by chat GPT for Openness sake... I suck at readme's
