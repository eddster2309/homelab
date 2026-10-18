# netbox-sync

Keeps NetBox a live inventory of JACK-CBR from OPNsense, Proxmox, Kubernetes,
FreeIPA DNS and Omada (CronJob in `../sync-deploy/`, every 5 minutes), then
exports NetBox into ClickHouse for NetFlow enrichment.

How it fits into the network monitoring system (diagram, naming precedence,
ownership/ageing rules, credentials, operations):
[netflow README](../../../../../infrastructure/infra/applications/netflow/README.md).

Tests: `uv run --with pytest,requests,netaddr,pydantic pytest tests`
