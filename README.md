# DNS System Project

## Overview

This project implements a simplified Domain Name System (DNS) comprising several key components that work together to resolve DNS queries. The system includes:

- **Root Server:** The top-level DNS server that directs queries to appropriate TLD servers.
- **Top-Level Domain (TLD) Server:** Handles queries for specific top-level domains such as `.com`, `.org`, and reverse DNS lookups like `in-addr.arpa`.
- **Authoritative Server:** Provides definitive DNS records for domains it manages.
- **Recursive Resolver:** Iteratively resolves DNS queries by communicating with the Root, TLD, and Authoritative servers.
- **DNS Utilities (`dns_utils.py`):** Contains helper functions for parsing and constructing DNS messages.

## Features

- Handles standard DNS record types including `A`, `AAAA`, `NS`, and `PTR`.
- Supports reverse DNS lookups.
- Implements a basic caching mechanism to optimize query resolution.
- Provides detailed logging for monitoring and debugging purposes.

## Components

- **`RootServer.py`**: Manages root-level DNS queries and delegates them to the appropriate TLD servers.
- **`TldServer.py`**: Processes TLD-specific queries and refers them to the corresponding Authoritative servers.
- **`AuthoritativeServer.py`**: Responds with authoritative DNS records for managed domains.
- **`RecursiveResolver.py`**: Resolves DNS queries by interacting with Root, TLD, and Authoritative servers, utilizing caching for efficiency.
- **`dns_utils.py`**: Utility module for encoding, decoding, and handling DNS messages.
