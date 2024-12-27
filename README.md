# Custom DNS Server Implementation

This repository contains a custom DNS server implementation in Python, including a Root Server, TLD Server, Authoritative Server, and DNS Utilities module. The servers are designed to work together to resolve DNS queries for specific domains as defined in their respective databases.

## Table of Contents
- Overview
- Features
- Prerequisites
- Installation
- Configuration
- Usage
- Project Structure
- Troubleshooting
- License

## Overview

The project simulates a hierarchical DNS system with three types of servers:

- Root Server: Handles the initial DNS queries and redirects them to the appropriate TLD servers.
- TLD Server: Handles queries for top-level domains like .com, .org, etc., and redirects them to authoritative servers.
- Authoritative Server: Holds the actual DNS records for domains and responds with the requested information.

The servers communicate over UDP sockets and use custom DNS utilities for parsing and building DNS messages.

## Features

- Custom implementation of DNS query and response handling
- Hierarchical server structure mimicking real DNS resolution
- Caching mechanisms to improve performance
- Support for common DNS record types: A, AAAA, MX, NS, PTR
- Logging of all DNS queries and responses

## Prerequisites

- Python 3.6 or higher
- Administrative privileges to bind to UDP ports below 1024 (or run servers on higher ports)
- Basic understanding of network programming and DNS concepts

## Installation

1. Clone the Repository
Clone the repository using git and navigate to the project directory:
git clone https://github.com/yourusername/custom-dns-server.git
cd custom-dns-server

2. Install Required Packages
The servers use only standard Python libraries, so no external packages are required.
Ensure you have Python 3.6 or higher installed.

## Configuration

### Server IP Addresses and Ports

Adjust the IP addresses and ports in each server script according to your network setup:

Root Server (root_server.py):
Set TLD_SERVER to ("(server device ip address from ipconfig)", 5301)

TLD Server (tld_server.py):
Set AUTH_SERVER to ("(server device ip address from ipconfig)", 5302)

Authoritative Server (auth_server.py):
Uses port 5302 by default

### DNS Records

Customize the DNS records in each server's database as needed:

Root Server Database includes entries for:
- com domain
- org domain
- reverse DNS entries

TLD Server Database includes entries for:
- google.com
- facebook.com
- wikipedia.org

Authoritative Server Database includes:
- A records
- AAAA records
- MX records
- NS records
- PTR records

## Usage

### Starting the Servers

Start each server in separate terminal windows in the following order:

1. Start the Authoritative Server:
   Run: python auth_server.py

2. Start the TLD Server:
   Run: python tld_server.py

3. Start the Root Server:
   Run: python root_server.py

### Testing DNS Resolution

You can test the DNS servers using nslookup or any other DNS query tool:

1. Query for an A Record:
   Use: nslookup google.com (server device ip address from ipconfig)

2. Query for an MX Record:
   Use: nslookup -type=MX google.com (server device ip address from ipconfig)

3. Reverse DNS Lookup:
   Use: nslookup -type=ptr 2.10.20.172.in-addr.arpa (server device ip address from ipconfig)

Note: Replace 192.168.1.4 with the IP address where your Root Server is running.

## Project Structure

- root_server.py: The Root DNS Server script
- tld_server.py: The TLD DNS Server script
- auth_server.py: The Authoritative DNS Server script
- dns_utils.py: Utility functions for parsing and building DNS messages
- dns_server.log: Log file where all servers write their logs

## Troubleshooting

### Permission Denied on Ports Below 1024
- Run scripts with elevated privileges or use ports above 1024

### Firewall Blocking Ports
- Ensure firewall allows UDP traffic on configured ports

### Address Already in Use
- Check for processes using the port
- Change port numbers if needed

### No Response to Queries
- Verify all servers are running
- Check IP addresses and port configurations
- Consult dns_server.log for error messages

## License

This project is open-source and available under the MIT License.
