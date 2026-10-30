# Network monitoring (NetFlow)

Records every flow that OPNsense routes. Each flow is stored in ClickHouse and enriched when it arrives with four things:

- **Location and network owner:** where the internet end is and who runs it (GeoIP, ASN).
- **The local host:** what the LAN end is, taken from NetBox. NetBox is kept current from OPNsense, Proxmox, Kubernetes, FreeIPA and Omada.
- **The domain:** the server name Suricata saw on the wire (TLS SNI, HTTP Host), or else which name the device looked up, from Blocky's DNS answers.
- **Reputation:** the cloud service or threat list the remote address belongs to.

The Grafana dashboards *Home Network Traffic* and *Host Traffic* are retired, with their generators; the data is queried directly. For a local host or IP it holds:
- identity from NetBox
- internet and LAN totals and throughput
- domains, remote networks and a map
- LAN peers, which link on to their own page
- services it uses and serves
- its DNS lookups
- findings: threat lists, external DNS, and reset-only connections to local services
- what Suricata saw: server names (TLS/HTTP), TLS client fingerprints (JA4), IDS alerts
- recent flows

```mermaid
flowchart LR
    subgraph sources["Sources (outside the cluster)"]
        OPN["OPNsense<br/>jack-cbr-fw01"]
        SURI["Suricata IDS on OPNsense<br/>eve.json → syslog-ng"]
        PVE["Proxmox<br/>hydrogen"]
        IPA["FreeIPA DNS"]
        OMADA["Omada OC200"]
        BLOCKY["Blocky DNS<br/>blocky01/02"]
        FEEDS["Public feeds<br/>MaxMind · Spamhaus · Feodo · Tor<br/>AWS · Google · Cloudflare · GitHub · M365 · IANA"]
    end

    subgraph netbox_ns["netbox namespace"]
        SYNC["netbox-sync<br/>CronJob · 5 min"]
        NETBOX[("NetBox<br/>inventory")]
    end

    subgraph netflow_ns["netflow namespace"]
        GOFLOW["goflow2<br/>LB REDACTED_IP:2055/udp"]
        EVE["eve-receiver (Vector)<br/>LB REDACTED_IP:5514/tcp"]
        KAFKA[["Kafka (Strimzi)<br/>topics flows, eve · 24h"]]
        CH[("ClickHouse<br/>netflow db")]
        DNSTAIL["dns-tail + dns-maint<br/>Deployments · 30 s / 2 min"]
        INTEL["intel-update<br/>CronJob · 6 h"]
        GEOIP["geoipupdate<br/>CronJob · weekly"]
    end

    subgraph monitoring_ns["monitoring namespace"]
        LOKI[("Loki")]
        GRAFANA["Grafana<br/>Home Network Traffic"]
    end

    CROWDSEC["CrowdSec LAPI<br/>crowdsec namespace"]

    OPN -- "NetFlow v9 (UDP)" --> GOFLOW --> KAFKA -- "Kafka engine" --> CH
    SURI -- "EVE JSON lines (TCP)" --> EVE -- "tls / http / alert" --> KAFKA
    OPN & PVE & IPA & OMADA -- "APIs" --> SYNC
    SYNC <-- "REST" --> NETBOX
    SYNC -- "nb_* tables" --> CH
    BLOCKY -- "query log (journald → Alloy)" --> LOKI -- "answers" --> DNSTAIL -- "dns_answers" --> CH
    FEEDS --> INTEL -- "intel_*, port_names" --> CH
    CROWDSEC -- "decisions" --> INTEL
    FEEDS --> GEOIP -- "CSV on NFS" --> CH
    CH --> GRAFANA
```

## How a flow gets enriched

```mermaid
flowchart TB
    Q["flows_queue<br/>(Kafka engine, goflow2 JSON)"] --> MV{{"flows_mv<br/>dictionary lookups at insert"}}
    MV --> F[("flows · 30 d")]
    F --> R5["flows_5m · 1 y<br/>remote side: country, ASN, geo"]
    F --> RL["flows_lan_5m · 1 y<br/>per LAN host tx/rx, peer, service"]
    F -. "dns-tail, buckets > 10 min old" .-> RD["flows_domain_5m · 1 y<br/>LAN host × domain"]
    F -. "dns-tail fixup, last 30 min" .-> F

    subgraph dicts["Dictionaries used by flows_mv"]
        D1["geoip_city_blocks / locations / asn<br/>(MaxMind CSV)"]
        D2["nb_host_dict / nb_prefix_dict / nb_service_dict<br/>(NetBox export)"]
        D3["dns_pair_dict / dns_ip_dict<br/>(Blocky answers, last 24 h)"]
        D4["intel_threat_dict / intel_cloud_dict<br/>(threat lists, cloud ranges)"]
    end
    dicts --- MV
```

| Column(s) on `flows` | Source | Meaning |
|---|---|---|
| `src/dst_country`, `_city`, `_lat/_lon`, `_asn`, `_as_org` | MaxMind GeoLite2 (IP_TRIE) | Where the internet end is and who owns it. Private addresses stay empty. |
| `src/dst_host`, `_host_kind` | NetBox → `nb_hosts` | Name and kind (`client`, `vm`, `k8s-node`, `k8s-vip`, `vip`, …) |
| `src/dst_segment` | NetBox prefixes → `nb_prefixes` | `users`, `kubernetes`, `cctv`, …, `Asher CBR`/`Asher MEL` (remote sites, prefixes from homelab-tf), or `internet` |
| (query time) `via` | OPNsense interface routes → `nb_prefixes.via` | The interface a prefix is reached over when it isn't a local VLAN, e.g. `INTER_WG_TO_CBR (wg1)` for the remote sites (the peers' AllowedIPs). Dashboards look it up with `dictGet('netflow.nb_prefix_dict', 'via', …)`; it isn't stored on flows. |
| `service` | NetBox services → `nb_services` | e.g. `traefik/traefik websecure`, `frigate`. Matched on dst:port, or src:port for return traffic. |
| `domain`, `domain_names` | Blocky answers → `dns_answers` → `conn_domains` | The name the client looked up to reach the server, chosen once per connection (see below). `domain_names` counts the names the client had for that IP: 1 means certain, more than 1 means a best guess. Works for LAN VIPs too: `REDACTED_IP` resolves to `cctv.0b.au` etc. |
| `remote_cloud` | Published ranges → `intel_cloud` | e.g. `AWS CLOUDFRONT ap-southeast-2`, `GitHub pages`, `Microsoft 365 Exchange` |
| `threat` | Threat lists → `intel_threat` | `spamhaus-drop`, `feodo`, `tor-exit`, `crowdsec` |
| `exporter` | `exporters` (`02-exporters.sql`), by `sampler_address` | The sensor that saw the flow: `opnsense`, `edge01`. An unlisted sensor shows its address. |
| `src/dst_local` | GeoIP, plus the exporters' own addresses in NetBox | 1 if that end is ours: GeoIP has no country for it, or it's an address NetBox has for an exporter host (edge01's public IPs, the home WAN). The rollups use these for direction and the LAN end. An exporter's own public address gets that exporter's segment (`edge`, `wan`) rather than `internet`. |
| `k8s_workload`, `k8s_pod` | Hubble → `k8s_conns` (`02-workloads.sql`), by 5-tuple | The pod behind a k8s node's end of the flow, `<namespace>/<name>`: `gitlab/gitlab-sidekiq-all-in-1-v2`. Pods leave the cluster masqueraded to their node's address, so without it the flow only says `k8s-node-2`. See [Kubernetes workloads](#kubernetes-workloads). |
| `k8s_workload`, `k8s_pod` (inbound) | Traefik's access log → `traefik_requests` (`02-traefik.sql`), by client and port | For flows to or from Traefik's VIP, the workload behind the service the client reached: `gitlab/gitlab-webservice-default`. Hubble's label wins when both match |
| `k8s_via` | which of the two labelled it | `''` = Hubble (the pod behind a node's end), `'traefik'` = the workload behind the Traefik VIP. Tells the two directions apart |

### How a flow gets its domain

0. **Seen on the wire (certain):** Suricata on OPNsense logs the server name of every TLS handshake (SNI) and plaintext HTTP request (Host). `05-eve.sql` writes each one straight into `conn_domains` for that connection with `names = 1` and `source = 'sni'`/`'http'`. This covers DNS-over-HTTPS, cached and hard-coded IPs, shared IPs and simultaneous lookups. The steps below fill in what it doesn't see: other protocols, QUIC (HTTP/3), and VLANs Suricata doesn't listen on.
   - **Through edge01 (certain):** HAProxy on edge01 logs one `edge-session` line per proxied connection as soon as its backend connection is up (a log-profile `connect` step, HAProxy 3.1+). dns-tail reads them from Loki into `edge_sessions`, and `09-edge.sql` writes the SNI into `conn_domains` for both legs of the session with `source = 'edge'`: the public leg edge01's softflowd sees (client → edge01:443) and the tunnel leg OPNsense sees (`REDACTED_IP:<port>` → Traefik `:8443`). Logged at connect rather than close, so a long websocket session is named from its first flow.
1. **Answers:** dns-tail stores every A record Blocky answers as `(time, client, ip, name)`. Blocked names (`REDACTED_IP`) are skipped.
2. **Provisional label at insert:** a flow first gets the client's *latest* name for the server IP, from `dns_pair_dict`. If the client never looked the IP up, it falls back to anyone's latest name for it (`dns_ip_dict`).
3. **Per-connection assignment:** every 2 minutes dns-tail assigns each new connection that Suricata didn't already name `(client, port, server, port, proto)` one name: the client's lookup of that IP **at or just before the connection started** (an ASOF join with 5s slack). The result goes in `conn_domains`. The fixup relabels the connection's flows with it, and later records of the same connection get it straight from `conn_domain_dict` at insert. A long stream therefore keeps the name it was opened with, even when the device looks up other names on the same IP meanwhile.

It's still a best guess wherever one IP carries several names:
- **Several lookups right before a connection:** e.g. Flux resolving several GitHub Pages-hosted Helm repos within a second of each other.
- **HTTP/2 connection reuse:** browsers reuse one connection for several names under the same certificate (`*.0b.au`), so a single connection genuinely carries several sites.

`domain_names > 1` marks these cases. The dashboards show `name (1 of N)` and a *certain* share. For TLS and HTTP, step 0 settles them; `conn_domain_dict` always prefers a `source` other than `dns`. HTTP/2 reuse remains: the SNI names the connection's first site only.

Enrichment happens **once, at insert**. A row keeps the names that were true when it arrived. Two things work around that:
- **`domain` fixup:** dns-tail relabels the last 30 minutes of flows every 2 minutes, using per-connection names, which also covers flows that arrived before their DNS answer.
- **Names on dashboards:** panels group LAN devices by IP and label them with the host's *current* NetBox name, so a renamed device stays one row. The name stored at ingest is only the fallback for addresses NetBox no longer has. The `peer` column of `flows_lan_5m` still holds LAN peers' names as they were at ingest.

## Components

| Component | Where | What it does |
|---|---|---|
| OPNsense NetFlow export | firewall | v9 to `REDACTED_IP:2055/udp` (v5 until 2026-10-16). v9 adds IPv6 flows; byte and packet counts depend on `goflow2-mapping.yaml`. |
| goflow2 | `goflow2-deployment.yaml`, `goflow2-mapping.yaml` | Decodes NetFlow and produces JSON to Kafka topic `flows`. The mapping file works around a v9 bug: OPNsense sends `OUT_BYTES`/`OUT_PKTS` as 0 after `IN_*`, goflow2 decodes both into `bytes`/`packets` so v9 arrives as 0, and the mapping copies `IN_*` into `in_bytes`/`in_packets`, which `flows_mv` uses. Its `formatter.fields` list must match the `flows_queue` columns. |
| Kafka | `kafka/` (Strimzi, KRaft, 1 node) | 24h buffer. ClickHouse can be down or its MV rebuilt without losing flows. |
| Suricata (OPNsense IDS) | firewall, configured by hand (see [Suricata](#suricata)) | Logs TLS handshakes, HTTP requests and alerts to `eve.json`. syslog-ng streams the lines over TCP using `eve/opnsense-syslog-ng.conf` |
| eve-receiver | `eve/receiver.yaml`, `eve/vector.yaml` | Vector: keeps tls/http/alert events, flattens them, drops the duplicate copy of traffic between two monitored VLANs, and produces to Kafka topic `eve`. Also takes pf's filterlog on `:5515` and produces blocks to `fwlog` (see [Firewall log](#firewall-log)). Nothing goes to Loki |
| hubble-shipper | `hubble/shipper.yaml`, `hubble/vector.yaml` | Vector DaemonSet: reads its node's Hubble egress log (Cilium's dynamic exporter), keeps one line per pod connection, and produces to Kafka topic `hubble`. Its second log, Traefik's packets to backend pods, goes to `hubble-pods` (see [Kubernetes workloads](#kubernetes-workloads)) |
| ClickHouse | `clickhouse/` (Altinity operator, 1 replica) | Storage, dictionaries, rollups. Schema in `clickhouse/schema/*.sql`, applied by `schema-job.yaml`. |
| geoipupdate | `geoip-cronjob.yaml` | Weekly MaxMind GeoLite2 City + ASN CSVs on the `geoip-db` NFS PVC |
| dns-tail, dns-maint | `enrich/dns-tail.yaml`; code in the homelab-network-ui repo, `services/dns-tail` (one image, `tail` and `maint` modes) | Blocky query log from Loki into `dns_answers`, edge01's HAProxy sessions into `edge_sessions`, Traefik's access log into `traefik_requests`, edge01's per-connection verdicts into `edge_events`, plus the domain and workload fixup and the `flows_domain_5m` rollup |
| intel-update | `enrich/intel_update.py`, `enrich/intel-update.yaml` | Every 6h: threat lists, cloud ranges and IANA port names into `intel_*` / `port_names` |
| netbox-sync | [`apps/infra/applications/netbox/sync/`](../../../../apps/infra/applications/netbox/sync) | Every 5 min: OPNsense + Proxmox + Kubernetes + FreeIPA + Omada into NetBox, then NetBox into `nb_*` |
| Dashboards | `dashboard/gen_health.py` | Generates the Grafana dashboard JSON for *NetFlow Pipeline* (pushed with gcx, not GitOps) |
| Metrics | `scrapes.yaml`, `kafka/metrics.yaml` | VictoriaMetrics scrapes: Kafka broker JMX + Kafka Exporter (consumer lag), goflow2, dns-tail. ClickHouse comes from the clickhouse-operator's metrics-exporter; intel-update pushes its per-feed results to vmagent |

### netbox-sync

Every run has five steps:
1. **Collect** from each source.
2. **Merge** into one set of hosts, keyed by MAC with IP as the fallback.
3. **Bootstrap** the NetBox scaffolding: tags, custom fields, roles.
4. **Reconcile:** diff against NetBox and write only what changed.
5. **Export** NetBox, as it now is, into ClickHouse.

What each source contributes:

| Source | Endpoint | Contributes |
|---|---|---|
| OPNsense | `https://REDACTED_IP` API (k8s nodes can't reach NET_MGMT REDACTED_IP) | ARP (presence), dnsmasq leases, static hosts and DHCP pools, Unbound overrides, VLANs, prefixes, firewall interfaces |
| Proxmox | `https://REDACTED_IP` | Node and PVE version, the node's NICs/bonds/bridges/VLAN interfaces, VMs with guest-agent IPs, OS, NIC VLANs, disks and tags. Extra `/32`s on a VM are keepalived VIPs, named via `VIP_NAMES` (`dns`). |
| Kubernetes | in-cluster SA | Nodes and their OS, LoadBalancer VIPs (FHRP groups + one Service per port, listing Traefik's hosts) and the Cilium pools they come from, selector-less `external-service-*` backends |
| Metrics | VictoriaMetrics (vmselect, tenant 0) | Physical hosts' make, model, SKU and serial (`node_dmi_info`), and their real NIC names and MACs (burned-in MAC with a link speed) |
| Wazuh | indexer `wazuh.internal:9200`, read-only user `grafana` | Each agent's listening ports (by process), OS and board serial |
| Frigate | `https://REDACTED_IP:8971/api/config` (auth off; nftables admits only the k8s range) | Camera names for camera IPs (from go2rtc stream sources) |
| BMC | Redfish on `BMC_HOSTS` (hydrogen's iLO 4, read-only login) | DIMMs, PSUs, BIOS/iLO firmware; marks the BMC's own port out-of-band |
| Home Assistant | websocket API `http://REDACTED_IP:8123` (non-admin user's token) | Names people gave devices, make/model, firmware, room (area); Zigbee/Bluetooth devices |
| Binary Lane | `api.binarylane.com.au` (garage's token) | VPSes (edge01) as cloud VMs |
| FreeIPA | `ipa01` JSON-RPC | Forward A records as a naming fallback (reverse zones aren't populated) |
| NetFlow | ClickHouse `netflow.flows`, hourly | Ports LAN hosts answer on (see *Services seen in NetFlow*) |
| Omada | `https://REDACTED_IP` OpenAPI + web API | Client names (a fallback, see below), its switches and APs (names, switch ports, topology), where each client connects (see *Physical connections*). The web API (the omada-exporter's login) adds live port state and AP uplink ports; it's optional. |

**Naming precedence**, first match wins:
1. Proxmox VM name
2. k8s node
3. OPNsense static host / Unbound override
4. A name someone gave the device in Home Assistant (`Christmas-Tree`)
5. Frigate camera name (`garage-door`)
6. Omada device name, for Omada's own switches and APs (`Lounge-Room-AP`, or `<model>-<mac tail>` while Omada still shows the MAC)
7. k8s external-service
8. IPA record
9. DHCP hostname
10. Home Assistant's own device name (`SHIELD-Android-TV`)
11. Omada hostname
12. Omada client name
13. `client-<mac tail>`

Omada's client name ranks last because it's rarely an alias. Unless someone renames the client in the controller, Omada stores the first name it detected and never updates it: both iPhones are `iPhone`, every camera is `Camera1`, and k8s-node-3 is `DESKTOP-BFN4IFK`. The OpenAPI can't tell the two apart. Names that still clash get the MAC tail appended (`iPhone-45a3`). Omada's switches and APs rank above DHCP because their DHCP hostname is only the model (`SG2210P`); they get host kind `network` and the `Network` device role.

**Physical connections** (from Omada's active clients):
- **Switches** get an interface per port, `1/0/<n>`. A port's Omada name (`Router Uplink`, `ILO`) becomes its label, and its profile goes in the description. Ports with the `Disable` profile are disabled.
- **Wired devices** get a cable from the interface carrying the MAC Omada saw to that switch port. This includes the firewall (`ix1` to SG3428 port 1), hydrogen and the k8s nodes.
- **Shared ports** get no cable: when two NetBox devices sit on one port, there's an unmanaged switch in between (jp-desktop behind the TL-SG105MPE on port 16). VMs share their hypervisor's port and don't count.
- **Wi-Fi devices** get a `wlan0` interface of the right 802.11 type (`rf_role` station), made a member of the SSID's wireless LAN. Each SSID is a NetBox wireless LAN, linked to its VLAN. The AP and band go in the interface description. NetBox wireless links are point-to-point, one per interface, so AP-to-client links aren't drawn.
- **APs** get `radio0`/`radio1` interfaces (`rf_role` ap) in every SSID, and a cable from `eth0` to their switch port. The port comes from the switch's `downlinkList` in the web API; the OpenAPI only names the switch.
- **Switch-to-switch uplinks** are cabled port to port (SG3428 `1/0/3` to the SG2210P's `1/0/8`), from the OpenAPI v2 `topology` endpoint, which gives the port at both ends.
- **Link speed:** each switch port gets its negotiated `speed` and `duplex` from the web API, cleared while the link is down, and so does the device interface cabled to it. The interface type stays what the port can do (`1000base-t`, `1000base-x-sfp` for SFP ports), so a gigabit port that negotiated 100M, like the JetKVM's, shows both. Without the web API, the speeds and types already in NetBox are kept.
- **The `connection` custom field** stays as a one-line summary, using the switch's or AP's NetBox name.
- **Hand-made cables win:** the sync only moves or deletes cables tagged `netbox-sync`. A cable you draw yourself on either end is left alone, along with that link. Inactive clients keep their last cable.

- **Switch ports carry their VLANs** from the Omada port profile:
  - A profile with every network becomes `tagged-all`, and one with some tagged networks becomes `tagged`.
  - Anything else becomes `access`, and so does the interface of a wired device on that port.
  - Omada's default VLAN 1 isn't in NetBox, so it's left out.

**Other enrichment:**
- **Platforms:** VMs get one from the guest agent's OS (`Debian 13`, `Fedora 44`), k8s nodes from their OS image, and hydrogen gets `Proxmox VE 9.2`.
- **VM placement:** every VM is placed on its Proxmox node's device. To allow that, hydrogen is put in the `pve-jack-cbr` cluster.
- **Omada switches and APs:** they get a TP-Link device type per model (`SG3428`), their serial number, and a `firmware` custom field.
- **DHCP pools:** OPNsense's dnsmasq pools become IP ranges ("DHCP pool, Users"), marked utilised so their addresses don't show as free. (Not marked populated: NetBox then refuses to create any address inside the pool, so new leases could never be recorded.) A pool overlapping a range someone else made, such as Terraform's `ip_ranges.tf`, is skipped.
- **IP status:** addresses in a pool get status `dhcp`, unless a dnsmasq static host or Unbound override covers them.
- **DHCP reservations:** a dnsmasq static host (address + MAC) that nothing holds right now, because the host is off or still on another address, is kept as a `reserved` address described "DHCP reservation for <name> (<MAC>)". It becomes `active` on the host's interface when the host turns up, and is deleted when the reservation is removed on OPNsense.
- **Stale leases:** leases in a network the firewall no longer has an interface on (a VLAN given a new subnet) are ignored; dnsmasq keeps them until they expire.
- **Interface structure:**
  - Hypervisors get their real NICs, bonds (`lag`), bridges (`bridge`) and VLAN interfaces (`virtual`, with `parent` and an access VLAN). A NIC links to its bond or bridge through `lag`/`bridge`. The Omada cable goes on the physical NIC beneath the bridge, not on `vmbr0`.
  - The firewall's VLAN sub-interfaces get their trunk NIC as `parent` and their VLAN as access. The trunk gets them all as `tagged`, and the shared MAC sits on the trunk.
  - VM interfaces get `access` mode in their Proxmox `tag`'s VLAN, or else in the VLAN of the bridge they're on, when that bridge is built on a VLAN interface.
  - These fields are only set on interfaces tagged `netbox-sync`.
- **keepalived VIPs:** each `vip <ip>` FHRP group is assigned to the VM interface holding the address right now (keepalived's MASTER), and follows it on failover.
- **VM disks and tags:** Proxmox disks become virtual disks (`scsi0`, `rootfs`, `mp0`, with the storage in the description), so NetBox totals the VM's disk itself. Proxmox tags become `pve-<tag>` NetBox tags, and they're removed when removed in Proxmox.
- **Hardware:** physical hosts with node metrics (hydrogen, nvr, the k8s nodes) get a real device type, e.g. `HP ProLiant ML110 Gen9` with part number `776935-B21`, and their serial. The DMI vendor becomes the manufacturer (`Dell Inc.` → `Dell`). QEMU guests are left to Proxmox. Their NICs get real names (`eno2`); a guessed `eth0` is renamed, keeping its cable and IPs. On hydrogen, the MACs move from the bridges to `eno1`/`eno2`.
- **k8s LoadBalancer pools:** each Cilium pool block becomes an IP range ("k8s LoadBalancer pool infranet"), tagged `sync-k8s` and marked utilised like the DHCP pools.
- **Parts (inventory items):** hydrogen's disks (model, serial, size, SMART, wearout; matched by serial), CPU and NIC/storage cards from Proxmox; its DIMMs and PSUs from the iLO; Zigbee/Bluetooth devices from Home Assistant on their coordinator (or the HA host). Each source only changes or removes the items it made.
- **Services from Wazuh:** each agent's listening ports, grouped by process (`blocky`: tcp+udp/53, tcp/4000), tagged `sync-wazuh`. They cover the NetFlow guesses for those ports. A dual-boot box's other-OS agent (same IP, different name) is ignored.
- **Cameras:** Frigate's names, the `Camera` role.
- **Rooms:** a Home Assistant area fills an empty NetBox location; a room set by hand wins.
- **OPNsense extras:** WAN port forwards as services on the firewall bound to the WAN address, whose `nat_inside` points at the one host behind them (if only one); remote-access WireGuard peers (`WG`) as their tunnel addresses with the last handshake as `last_seen` (active within 7 days, else deprecated); gateways as described IPs. The inter-site WireGuard mesh stays Terraform's.
- **Cloud VMs:** Binary Lane servers in a `Binary Lane <region>` cluster (type Cloud), public addresses on `eth0`, private on `eth1`; the WireGuard peer connecting from its public address gets its tunnel address on `wg0`.
- **DNS (netbox-dns plugin):** FreeIPA's zones with its SOA/nameserver. The LAN prefixes are in the default view, so DNSsync makes A/AAAA records linked to each IP from its `dns_name` (and PTRs in the reverse zones); IPA's other records (alias A such as the ingress names, CNAME, SRV, MX) are mirrored as plain records, aliases without PTR. FreeIPA-enrolled hosts get the `ipa-enrolled` tag.
- **Tenancy and grouping:** objects the sync makes get the site's tenant. VLANs it creates go in the site's VLAN group (Terraform's, slug = site slug). Physical k8s nodes are put in the `k8s-jack-cbr` cluster (type Kubernetes, env `K8S_CLUSTER`).

**Services seen in NetFlow.** Every hour, netbox-sync looks for LAN addresses that answer from one fixed port (below 32768) to at least 5 different client ports over the last 7 days. That pattern is a server, and the opposite pattern is a client.
- **Where it goes:** each match becomes a NetBox service on the device, VM or VIP owning the address, named by IANA (`https`, `ldaps`, `proxmox`). Ports under the same name on one host share a service (`domain` = tcp+udp/53).
- **Tags:** it's tagged `sync-flows`.
- **Skipped:** ports a Kubernetes or hand-made service already covers.
- **Removed:** a service that drops out of the 7-day window.
- **What it can't see:** only routed (inter-VLAN) traffic reaches NetFlow, so a service used only within its own VLAN isn't found.
- **Curating:** to rename or keep one, remove its `sync-flows` tag. It then counts as hand-made: it covers its ports, and the sync leaves it alone.

The export puts these services in `nb_services`, so new flows get them in their `service` column.

**Rules the sync follows:**
- **Ownership:** everything it creates is tagged `netbox-sync`. It never changes or deletes untagged objects, apart from filling empty prefix descriptions and VLAN links.
- **Your edits win:** tag an object `sync-locked` and the sync won't change its name, description or DNS name.
- **Ageing:** clients unseen for 7 days go `offline` and are deleted after 30. VMs and hypervisors are only ever marked, never deleted. Addresses unseen for 7 days go `deprecated`; once no source lists them at all they are deleted after 30.
- **Removed networks:** an interface, VLAN or network deleted on OPNsense goes from NetBox on the next run, with the firewall's address in it. Addresses in a network the firewall no longer has are deleted once unseen for 6 hours. A VLAN or prefix someone else made (Terraform) is not deleted, only logged as a warning each run: remove it where it is managed.
- **Grafana links:** addresses, and devices and VMs with a primary IP, get a *Traffic (Grafana)* button in NetBox that opens **Host Traffic** for that address. They are NetBox custom links (`grafana-host-traffic*`) the sync creates, rendered on each page view.
- **Source outages:** a source that fails a run ages nothing out, and doesn't rename or untag anything it owns.

## Data and retention

| Table | Retention | Notes |
|---|---|---|
| Kafka topic `flows` | 24h / 5 GiB | Buffer only. goflow2 produces zstd (~10× smaller than raw JSON) |
| Kafka topic `eve` | 24h / 1 GiB | Buffer only (Vector, zstd) |
| `eve_tls`, `eve_http`, `eve_alert` | 30 days | Suricata events, with NetBox names and ASN added at insert |
| Kafka topic `fwlog` | 24h / 1 GiB | Buffer only (Vector, zstd) |
| `fw_blocks` | 30 days | One row per packet pf blocked (WAN-inbound excluded), with NetBox names and segments added at insert |
| `flows_blocked_5m`, `flows_blocked_lan_5m`, `flows_blocked_domain_5m` | 1 year | Blocked twins of the rollups: same columns and keys, only flows that were blocked connection attempts. Filled by dns-tail's `rollup_blocked` per settled bucket (cursor `fw_rollup_cursor`) |
| `flows` | 30 days | One row per flow, all enrichment columns |
| `flows_5m`, `flows_lan_5m`, `flows_domain_5m` | 1 year | Rollups; dashboard panels use these for long ranges |
| `flows_port_1h`, `fw_blocks_1h`, `dns_queries_1h`, `eve_tls_daily`, `k8s_conns_daily`, `host_daily_stats`, `lan_asn_first_seen` | 1 year | Retention rollups (`12-retention.sql`): ports, pf blocks by rule, DNS lookups, TLS fingerprints, k8s egress, per-host daily stats, first contact per LAN host and AS. MVs; the backfills only run into an empty table |
| `flows_seg_1h`, `flows_svc_1h`, `flows_wan_1h`, `dns_pairs_1h` | 90 days | Hourly rollups for the netflowui Security pages (`19-security-rollups.sql`): LAN segment pairs, flows to service ports (exposure), flows to the internet (resolver bypass, lookup-only), each with its blocked count, and the (client, name, address) DNS answers. The flow ones are filled by dns-tail (`rollup_seg`, `rollup_svc`, `rollup_wan`) per settled bucket; `dns_pairs_1h` is an MV |
| `host_class` | 90 days | One row per LAN host from netflowui's device classifier, written hourly: class, score, evidence (`13-classify.sql`). Replaced each run; `host_class_dict` serves the query bar's `class:` filter |
| `dns_answers` | 30 days | Domain dictionaries only look at the last 24h |
| `edge_sessions` | 30 days | One row per session HAProxy on edge01 proxied: client (with country and ASN), the address it reached, both ends of the tunnel leg, backend, SNI. Refused sessions aren't in it (see `edge_events`) |
| `edge_events` | 30 days | One row per verdict on a public connection to edge01: which layer (`nftables`, `haproxy`) served or dropped it and why (`reason`), client (with country and ASN), port, SNI, bytes, duration. nftables rows are a rate-limited sample (`sampled = 1`) |
| Kafka topic `hubble` | 24h / 1 GiB | Buffer only (Vector, zstd) |
| Kafka topic `hubble-pods` | 24h / 1 GiB | Buffer only (Vector, zstd) |
| `k8s_pods` | 30 days | Which pod owns an address, one row per pod per hour while Traefik talks to it. Backs `k8s_pod_dict` (last day) |
| `traefik_requests` | 30 days | One row per request Traefik served to a client outside the cluster (pods' requests are skipped): client (with LAN host name or country), entrypoint, host, router, Service, backend pod and workload, status, bytes, duration, protocol, User-Agent, TLS version and cipher, basic-auth user. Not the path |
| `k8s_conns` | 30 days | One row per pod connection that left the cluster, or was dropped on its way out: node and its address, pod, workload, the 5-tuple before masquerade, verdict |
| `nb_*`, `intel_*`, `port_names` | replaced each refresh | Filled as `<t>_new`, then `EXCHANGE TABLES`, so dictionaries never see a half-written table |
| ClickHouse `system.*_log` | 7 days | Its own query/trace/metric logs. Set in `chi.yaml` (`config.d/system_logs.xml`); several default to never expiring |

Footprint at ~2.7M flows/day (measured on the first full day, 2026-10-01: `flows` compresses to ~45 B/row):
- **ClickHouse:** ~1.5 GB for 30 days of `flows`, under 1 GB/year for the rollups, about 150 MB of DNS answers, and 1–2 GB of system logs. The Suricata tables are estimated at under 1 GB for 30 days (~200–400k events/day).
- **Kafka:** roughly 300 MB for the 24h `flows` buffer, plus under 100 MB for `eve`.
- **Longhorn:** keeps 3 replicas of each volume, so multiply by 3 for node disk.
- **RAM:** ClickHouse holds about 750 MB of dictionaries, mostly GeoIP city blocks.

## Access and credentials

| ClickHouse user | Used by | Rights |
|---|---|---|
| `admin` | schema Job, humans | Everything |
| `grafana` | Grafana datasource `clickhouse-netflow` | Read-only (`readonly=2`) |
| `netbox_sync` | netbox-sync | `netflow.nb_*` only |
| `enricher` | dns-tail, intel-update | Its own tables, `ALTER UPDATE` on `flows`, `dictGet` |

Vault (`k8s-infra` mount on `vault.internal`):

| Path | Properties |
|---|---|
| `netflow/clickhouse` | `admin_password`, `grafana_password`, `netbox_sync_password`, `enricher_password` |
| `netflow/crowdsec` | `bouncer_key` (the `netflow` CrowdSec bouncer; also read by the crowdsec namespace) |
| `netbox/sync` | `netbox_token`, `opnsense_key`, `opnsense_secret`, `ipa_user`, `ipa_password` |
| `netbox/proxbox/credentials` | Proxmox API token (`user`, `token_id`, `token_secret`, `domain`) |
| `omada-exporter/credentials` | Omada OpenAPI client (`id`, `secret`), shared with omada-exporter |
| `maxmind/credentials` | GeoLite2 download |

## Operating it

**Add a flow sensor.** Add a row to the `INSERT` in `clickhouse/schema/02-exporters.sql`: its `sampler_address` as goflow2 sees it (the address its packets arrive from), a short `name`, its NetBox name as `host`, and a `role`. Every address NetBox has for that host then counts as local. Export only what no other sensor sees, so nothing is counted twice. For edge01 that means public `eth0` only, without the WireGuard port, since OPNsense already sees wg0. Every rollup and blocked twin is keyed by `exporter`. Rows from before 2026-10-16 have `exporter = ''`, which means OPNsense, so filter with `exporter IN ('opnsense', '')`.

**Name something.** Rename the device in NetBox and tag it `sync-locked`, or add an OPNsense static host. An Omada alias only counts for devices that send no DHCP hostname. New flows carry the name within about 7 minutes (one sync plus a dictionary reload). The dashboard's *Unidentified hosts* panel is the to-do list.

**Change the schema.** Edit `clickhouse/schema/*.sql`. The ConfigMap hash changes, so Flux recreates the Job, which re-runs every file in order:
- New columns go in as `ALTER TABLE … ADD COLUMN IF NOT EXISTS`.
- `flows_mv` is dropped and recreated on every run. That's safe, because Kafka holds flows while no MV is attached.
- The Job can fail a few times while ClickHouse restarts: its Service is headless, so the name vanishes with the pod. It retries.

**Backfill enrichment onto old flows** after adding a new lookup:

```sql
ALTER TABLE netflow.flows UPDATE <column> = <same expression as flows_mv> WHERE 1
SETTINGS mutations_sync = 2, allow_nondeterministic_mutations = 1;
```

Then rebuild any affected rollup for the backfilled period: delete its buckets and `INSERT … SELECT` from `flows` with the rollup's query. Do this on a 5-minute bucket boundary so nothing is double-counted.

**Update the dashboard:**

```bash
cd dashboard && python3 gen_health.py && gcx resources push -p netflow-pipeline.json
```

**Run the tests:**

```bash
# from this directory
# netbox-sync and dns-tail live in GitLab homelab/homelab-network-ui (services/), with their own tests: cd services/<name> && uv run pytest
(cd enrich && uv run --no-project --with pytest,requests pytest tests)   # intel-update
```

**Check health:** Grafana's **NetFlow Pipeline** dashboard (uid `netflow-pipeline`) covers goflow2, Kafka lag, ClickHouse table sizes and dictionaries, the enrichers, and Suricata EVE. By hand:

```bash
kubectl -n netbox logs job/$(kubectl -n netbox get jobs -o name | grep netbox-sync | tail -1 | cut -d/ -f2)   # expect writes 0/0/0
kubectl -n netflow logs deploy/dns-tail --tail=20   # Loki tailers; deploy/dns-maint for the rollups
kubectl -n netflow exec chi-netflow-netflow-0-0-0 -- clickhouse-client -q \
  "SELECT name, status, element_count, last_exception FROM system.dictionaries WHERE database='netflow'"
kubectl -n netflow exec chi-netflow-netflow-0-0-0 -- clickhouse-client -q \
  "SELECT length(exceptions.text), num_messages_read FROM system.kafka_consumers"
```

### Suricata

Suricata runs in IDS mode on OPNsense. It only listens; it never blocks. Its `eve.json` reaches ClickHouse without going through Loki:
- syslog-ng on the firewall sends the raw lines over TCP to `REDACTED_IP:5514`
- eve-receiver keeps tls, http and alert events and produces them to the Kafka topic `eve`
- the `eve_queue` Kafka engine table feeds the `eve_*_mv` views, which write the `eve_*` tables
- `conn_domains_sni_mv` / `conn_domains_http_mv` copy the names into `conn_domains`

The firewall side is manual:
1. **Services → Intrusion Detection → Administration:**
   - Enable it. Leave IPS mode and promiscuous mode off.
   - Interfaces: the client VLANs (users, guest, WireGuard). Add `kubernetes` once firewall CPU looks fine. Leave out `legacy-services`, where the NFS traffic comes from.
   - Enable EVE TLS logging with *extended* (adds JA4) and EVE HTTP logging. Keep the logs for 1–2 days.
   - Rulesets aren't needed for names. Enable ET Open categories only if you want `eve_alert`, since rules are where the CPU goes.
2. **syslog-ng drop-in:** copy `eve/opnsense-syslog-ng.conf` to `/usr/local/etc/syslog-ng.conf.d/netflow-eve.conf`. Check it with `syslog-ng --syntax-only`, then restart the syslog service (System → Log Files → General, or `configctl syslog restart`). The file lives outside OPNsense's config, so a reinstall or factory reset loses it. Keep this repo copy current.

Check it: `tail -f /var/log/suricata/eve.json | grep '"tls"'` on the firewall, then `kubectl -n netflow logs deploy/eve-receiver` and the *Suricata EVE* row of NetFlow Pipeline.

What the OPNsense template allows: `eve.json` only carries the types the UI exposes (alert, anomaly, http, tls, drop, ssh). **QUIC (HTTP/3) and DNS events aren't available.** Adding them means overriding OPNsense's Suricata outputs list through `/usr/local/etc/suricata/conf.d/`, which merges by list index and is fragile. QUIC traffic therefore still gets its name from DNS.

### Firewall log

NetFlow can't say whether pf passed or blocked a packet: `ng_netflow` taps the interface before pf, so a blocked connection attempt is still a flow. pf's own log (filterlog) is the record of what was blocked:
- OPNsense's remote syslog target sends filterlog lines over TCP to `REDACTED_IP:5515`
- eve-receiver's `fw` transform keeps only `block`/`reject` lines. It drops blocks inbound on the WAN (internet scans; edge01 already covers the public side) and produces the rest to the Kafka topic `fwlog`
- the `fw_queue` Kafka engine table feeds `fw_blocks_mv`, which writes `fw_blocks` (`06-fwlog.sql`)
- netflowui matches `fw_blocks` to flows on the 5-tuple at query time to mark blocked flows, and shows them under Security → Firewall
- the rollups have no ports, so dns-tail's `rollup_blocked` step writes their blocked twins (`07-fw-rollup.sql`): every settled 5-minute bucket, the same rollup SELECTs over only the flows whose 5-tuple was a blocked connection attempt. Pages subtract them to show allowed traffic
- only connection attempts count as blocking a flow: a TCP SYN without ACK, or any UDP/ICMP packet. pf's default deny also logs stray ACK/FIN/RST packets of connections it already passed (after their state expired); those stay in `fw_blocks` but don't mark flows

The firewall side is manual:
1. **Firewall → Settings → Advanced:** keep "Log packets matched from the default block rules" on. Tick **Log** on any of your own block/reject rules; pf doesn't log unlogged rules, so their blocks won't appear.
2. **System → Settings → Logging → Remote → add:** transport TCP4, host `REDACTED_IP`, port `5515`, applications **filter (filterlog)**, level info, RFC5424 on. It's GUI config, so it survives upgrades.
3. **`WAN_IFACES`** in `eve/receiver.yaml` is the WAN device name(s) (comma-separated) as filterlog prints them, which is the device column in Interfaces → Assignments, e.g. `igc0` or `pppoe0`. While it's unset or still `TODO`, the `fw` transform errors and drops everything (see `vector_component_errors_total`), so internet scans never flood in.

Check it: Firewall → Log Files → Live View on the firewall, then `kubectl -n netflow logs deploy/eve-receiver` and `SELECT * FROM netflow.fw_blocks ORDER BY ts DESC LIMIT 10`. The `fw` transform's tests are in `eve/vector-tests.yaml`; the command to run them is at the top of that file.

### Edge verdicts

For a public connection to edge01 (:443, the :80 redirect, GitLab SSH), which layer refused it and why. Three layers, in the order a connection meets them; `edge_events` (`11-edge-events.sql`) holds one row per verdict, read from Loki by dns-tail's `edge_events` step:

| Layer | Drops | `reason` | In `edge_events` |
|---|---|---|---|
| nftables on edge01 | Silently, by policy (no RST, no ICMP) | `geo` (source not in the AU set), `hosting` (cloud/hosting ASN), `rate-source` (one source over its own budget), `rate-global` (AU source over the aggregate cap), `port` (AU source, port not served), `invalid` | `layer = 'nftables'`, **sampled** |
| HAProxy on edge01 | `silent-drop`, after the TCP handshake | `conn-rate`, `conn-limit` (per-source tracking), `not-tls`, `no-sni`, `unknown-sni` (:443), `unknown-host` (:80); served connections are `served` (`redirect` on :80) | `layer = 'haproxy'`, every session |
| Traefik on the cluster (CrowdSec bouncer + AppSec) | A 403 | not recorded | not in `edge_events`: Traefik's logs name neither the IP nor the decision, so it shows only as `traefik_requests.status = 403` with an empty `svc_name` |

CrowdSec's and fail2ban's own nftables tables on edge01 drop at priority -10, ahead of the `edge` table, and log nothing; they're only in those tools' metrics. A connection they drop never reaches the layers above.

- **HAProxy:** the close line of every frontend ends in `fp=<port> v=<verdict>` (garage `haproxy.cfg.j2`; the per-source limits are judged in `tcp-request content` rules, because HAProxy writes no log line for a session rejected at connect time). `action` is `served` for `served`/`redirect` and `drop` otherwise; `aborted` is a client that left before any rule decided. The `edge-session` connect line (`edge_sessions`) is a different line and isn't read here. Lines from before the verdicts existed are given a reason from what's left: no backend and no SNI is `no-sni-or-not-tls` (the two were not told apart), no backend with an SNI `unknown-sni`, other `http_in`/`ssh_in` drops `unknown-drop`
- **Time zone:** HAProxy's `[%tr]` is edge01's local time with no zone (AEDT, +11). dns-tail takes the offset from the Loki line's own time (the session started `%Tt` before the close line was logged; the difference, rounded to 15 minutes, is the offset), so it follows daylight saving instead of hard-coding it
- **nftables:** the kernel log line `edge-drop <reason>: ... SRC= ... PROTO= SPT= DPT=` that Alloy labels `firewall="input_drop"`; the older `edge-input-drop:` (no reason) is stored as `unknown-drop`. Each reason has its own rate limit (`nftables_log_input_drops_rate`, 2/s burst 20), so **a row is an example of a drop, not every one**: use it to see who and what, never to count. The exact totals per reason are Prometheus' `edge_nft_counter_packets_total{counter="input_geo"|"input_hosting"|"input_ratelimit_web"|"input_ratelimit_ssh"|"input_ratelimit_global"|"input_port"|"input_invalid"}`, exported by `edge-metrics.sh`. The time is the Loki line's; ICMP rows have ports 0
- Two Loki queries, so two cursors (`max(logged)` per `layer`): `EDGE_EVENTS_HAPROXY_LOKI_QUERY` and `EDGE_EVENTS_NFT_LOKI_QUERY`. A failure in one layer doesn't hold up the other, nor the DNS and edge-session steps. Metrics: `dns_tail_edge_events_stored_total{layer}`, `dns_tail_edge_events_cursor_timestamp_seconds{layer}`

Check it: rows per layer and reason, and that the cursors advance:
```sql
SELECT layer, reason, count() AS n, any(sampled) AS sampled FROM netflow.edge_events
WHERE ts > now() - INTERVAL 1 HOUR GROUP BY layer, reason ORDER BY layer, n DESC
```
Before edge01 is redeployed with the new config, only the derived reasons (`no-sni-or-not-tls`, `unknown-sni`, `unknown-drop`, `served`, `redirect`) appear. After it, every row has an exact reason, and no `unknown-drop` rows should be newer than the deploy.

### Kubernetes workloads

Pods leave the cluster masqueraded to their node's address (Cilium `bpf.masquerade`), so OPNsense records `k8s-node-2:49762 → REDACTED_IP:443` and nothing about which pod it was. Hubble knows the pod, and masquerade keeps the pod's source port (checked on Cilium 1.19: every sampled connection matched), so the two records share the 5-tuple `(node address, source port, destination, port, protocol)`. Hubble only names the pod; its events have no byte counts, so NetFlow still measures the traffic, and Hubble isn't an exporter.

- Cilium's **dynamic exporter** (`cilium/cilium-helmchart-config.yaml`, exporter `egress`) writes each node's pod connections to anything outside the cluster (`reserved:world`, which includes other VLANs) to `/var/run/cilium/hubble/egress.log`, plus drops on the way out. A second exporter, `pods`, writes `/var/run/cilium/hubble/pods.log` (Traefik's packets to pods, for the destination pod's name) Its filters live in the `cilium-flowlog-config` ConfigMap, which the agents re-read without restarting
- **hubble-shipper**, a Vector DaemonSet, reads its node's file, keeps the first event per connection, stamps the node's InternalIP (`status.hostIP`) as `node_ip`, and produces to Kafka topic `hubble`
- `k8s_conns_queue` → `k8s_conns_mv` → `k8s_conns`; `k8s_conn_dict` holds the last day's forwarded connections by 5-tuple
- `flows_mv` fills `k8s_workload`/`k8s_pod` at insert when the dictionary already has the connection. Usually it doesn't: OPNsense's record lands within seconds of Hubble's SYN and the dictionary reloads every 20–40 s, so dns-tail's fixup labels most of them within one pass (2 minutes). It only ever adds a label
- the rollups don't carry the workload, so it's only there for the 30 days of raw flows
- dropped connections never reach the network, so they're only in `k8s_conns` (`verdict = 'DROPPED'`): cluster-side policy blocks, next to pf's `fw_blocks`

Not covered by Hubble: pod↔pod and node↔node traffic (WireGuard between nodes, on one subnet, so OPNsense never sees it), and pods on the host network (they already show as the node). Inbound traffic is labelled from Traefik instead:

#### Inbound through Traefik

Every service is reached through Traefik's VIP (`REDACTED_IP`, `k8s-vip` in NetBox, which also carries rsyslog), so OPNsense records `client:port → REDACTED_IP:443`. Traefik's JSON access log has the same `client:port` for each request, plus the Service and the backend pod's address. Cilium's DSR keeps the client's address and port, so they match OPNsense's flow exactly.

- dns-tail's `traefik` step reads `{namespace="traefik", container="traefik"} |= "ClientAddr"` from Loki (own cursor, like `edge`) into `traefik_requests_queue` → `traefik_requests_mv` → `traefik_requests` (`10-traefik.sql`). Requests from pods (`POD_CIDRS`, default `REDACTED_IP/16`) are skipped: they never cross OPNsense, so they can't label a flow, and they're about three quarters of the log. That leaves about 6–7k requests/h, 30 days. `RequestPath` and the query string are not kept
- the backend's `ip:port` becomes a workload through `k8s_pod_dict` (`02-workloads.sql`). A second Cilium dynamic exporter, `pods`, logs Traefik's packets to its backends (they name the destination pod); hubble-shipper keeps one line per pod per hour in Kafka topic `hubble-pods` → `k8s_pods`. A backend that isn't a pod (Proxmox, Frigate via an external Service) has `backend_workload = ''` and is attributed to its Service, `<svc_namespace>/<svc_name>`
- `traefik_conn_dict` is keyed `(client, client_port)` for `websecure` (:443): the workload with the most bytes on that connection over the last day, its pod, and `names`, the workloads it reached (HTTP/2 can carry several hosts). `02-traefik.sql`
- `websecure-pub` (:8443) is edge01's tunnel leg. Traefik logs the internet client (PROXY protocol); OPNsense records `REDACTED_IP:<port> → VIP:8443`. `traefik_edge_conn_dict` joins the two through `edge_sessions` (same client and port) and is keyed by edge01's `(proxy_addr, proxy_port)`. So internet client → edge01 → OPNsense → Traefik → workload, with both legs labelled
- TCP entrypoints (`:222` gitlab-shell, `:8554` frigate-rtsp) have no access log. `traefik_tcp_routes` maps the VIP's port to a workload by hand (one row per IngressRouteTCP, replaced on every schema run); only `:222` exists so far
- `flows_mv` and dns-tail's fixup use these for flows whose other end is the Traefik VIP (`k8s-vip` named `traefik/traefik`, TCP): client → `:443` and the VIP's replies by `(client, port)`, edge01 → `:8443` and replies by edge01's port, then the TCP ports. Hubble's label is tried first, and a label is only ever added. `k8s_via = 'traefik'` marks them
- the same row also keeps the User-Agent, TLS version and cipher, and basic-auth user. Traefik can't compute a JA4 itself: for a LAN client, Suricata's `eve_tls` has it on the same `(src, src_port)` as the request's `(client, client_port)`, so the two can be joined later. Not done yet

Gaps: requests are logged when they finish, so a long websocket or download is labelled only once it ends, and the fixup only reaches back 30 minutes. The rollups don't carry the workload. edge01's own flows (client → its public IP) aren't labelled, only the tunnel leg. A new backend pod's first requests can fall back to the Service name until `k8s_pod_dict` loads it (20–40 s). Alloy drops metric and log ingest routed through Traefik on its way to Loki (`traefik-patch.yaml`), but that is Alloy's own pushes: Traefik's log of those requests (`vmauth-ingest`) is in Loki, so they are labelled.

Check it: `traefik_requests` growing and `dns_tail_traefik_cursor_timestamp_seconds` advancing, then coverage:
```sql
SELECT countIf(k8s_workload != '') / count() FROM netflow.flows
WHERE dst_addr = 'REDACTED_IP' AND dst_port IN (443, 8443) AND time_received BETWEEN now() - INTERVAL 1 HOUR AND now() - INTERVAL 5 MINUTE
```

Check it: `SELECT node, workload, count() FROM netflow.k8s_conns WHERE ts > now() - INTERVAL 10 MINUTE GROUP BY ALL`, then coverage:
```sql
SELECT countIf(k8s_workload != '') / count() FROM netflow.flows
WHERE src_host_kind = 'k8s-node' AND NOT dst_local AND time_received BETWEEN now() - INTERVAL 1 HOUR AND now() - INTERVAL 5 MINUTE
```
The shipper's transform tests are in `hubble/vector-tests.yaml`, with the command at the top. If coverage drops, check that masquerade still keeps ports: compare `kubectl -n kube-system exec ds/cilium -c cilium-agent -- hubble observe --to-identity world --type trace:to-stack -o jsonpb` with `flows` for the same node and destination.

## Gotchas

- **Manual sync runs can race.** Don't `kubectl create job --from=cronjob/netbox-sync` while a scheduled run is active. `concurrencyPolicy: Forbid` only covers the CronJob's own Jobs. The sync removes duplicate VIPs it finds, but a race still costs a messy run.
- **Omada is slow.** The OC200 sometimes takes over 60s. Omada calls have a 120s timeout and a retry, and a failed Omada run changes nothing.
- **Load-balancer IPs in ARP.** They appear with a k8s node's MAC, so they're excluded from MAC merging. In Omada a node's "IP" can be a VIP, so Omada is matched by MAC only.
- **Same-subnet traffic is invisible.** NetFlow only sees what OPNsense routes. Two devices on the same subnet talk through the switch, not the firewall.
- **DNS gaps.** Devices using DNS-over-HTTPS or hard-coded IPs get no `domain` unless Suricata sees a TLS SNI or HTTP Host for the connection. QUIC/HTTP3, STUN/VoIP and ECH (encrypted SNI) still go unnamed. The *DNS coverage* panel shows the matched share.
- **Suricata only sees the VLANs it listens on.** On the firewall, two monitored VLANs see the same connection twice; eve-receiver drops the second copy.
- **Vector's Kafka producer can wedge after a broker restart.** It keeps a stale "no leader" view of the partition and drops every event (`MessageTimedOut`) until restarted. eve-receiver and hubble-shipper have a liveness probe (`vector-kafka-liveness.sh`) that restarts them after three minutes of Kafka drops. A broker outage longer than that restarts them too, which is harmless.
- **CrowdSec runs offline** (`DISABLE_ONLINE_API`), so the `crowdsec` threat source only holds local decisions, not the community blocklist.
