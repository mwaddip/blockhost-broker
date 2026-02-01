# blockhost-broker TODO

## High Priority

- [ ] **NAT64 gateway on broker** - Enable IPv4 connectivity over IPv6 tunnel
  - Prevents Blockhost host IP exposure (all traffic exits via broker)
  - Install Jool (kernel) or Tayga (userspace)
  - Configure DNS64 for automatic AAAA synthesis
  - Document firewall rules for Blockhost hosts to block direct IPv4

## Features

- [ ] Client library for blockhost-provisioner integration
- [ ] Debian package (.deb) for easy installation
- [ ] HTTPS/TLS for API server
- [ ] Web dashboard for monitoring
- [ ] Automatic peer cleanup (remove stale allocations)
- [ ] Usage metering per allocation

## Improvements

- [ ] Fix CLI `peers` command to work without sudo (or document sudo requirement)
- [ ] Persist WireGuard config to disk on peer changes
- [ ] Add rate limiting to API
- [ ] Limit allocation pool to practical range (not 2^56 subnets)
- [ ] Systemd watchdog integration

## Future / Stretch

- [ ] Multiple upstream providers (failover)
- [ ] Tie allocations to on-chain identity (wallet address)
- [ ] Geographic distribution (multiple broker instances)
- [ ] Prefix delegation (/48 for larger operators)
