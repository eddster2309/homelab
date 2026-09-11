import requests
import urllib3
import ipaddress
from django.contrib.contenttypes.models import ContentType
from django.db.models import ForeignKey as DjangoFK
from extras.scripts import Script, StringVar, BooleanVar
from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site, Interface, MACAddress
from ipam.models import IPAddress, VLAN, Prefix
from virtualization.models import VirtualMachine, VMInterface

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class OPNsenseSyncScript(Script):
    class Meta:
        name = "OPNsense Sync"
        description = "Sync Interfaces, IPs, and ARP table from OPNsense to NetBox"
        commit_default = True

    Tunnel = None
    TunnelGroup = None
    TunnelTermination = None
    TunnelEncapsulation = None
    vpn_available = False

    opnsense_url = StringVar(
        description="OPNsense URL (e.g., https://REDACTED_IP)",
        default="https://REDACTED_IP"
    )
    api_key = StringVar(
        description="OPNsense API Key"
    )
    api_secret = StringVar(
        description="OPNsense API Secret"
    )
    device_name = StringVar(
        description="Name of the Firewall (Device or VM) in NetBox",
        default="OPNsense-Firewall"
    )
    is_virtual_machine = BooleanVar(
        description="Is this a Virtual Machine? (Uncheck if it is a physical Device)",
        default=True
    )
    site_slug = StringVar(
        description="Slug of the Site/Cluster where the firewall is located",
        default="lab"
    )
    verify_ssl = BooleanVar(
        description="Verify SSL Certificate",
        default=False
    )

    def run(self, data, commit):
        self.opnsense_url = data['opnsense_url']
        self.auth = (data['api_key'], data['api_secret'])
        self.verify = data['verify_ssl']
        self.device_name = data['device_name']
        self.is_vm = data['is_virtual_machine']
        self.site_slug = data['site_slug']

        self.import_vpn_models()

        self.sess = requests.Session()
        self.sess.auth = self.auth
        self.sess.verify = self.verify

        obj = self.sync_object()
        if not obj:
            return "Failed to find/create firewall object."

        interfaces = self.get_opnsense_interfaces()
        self.sync_interfaces(obj, interfaces)

        wg_clients = self.get_wireguard_clients()
        self.sync_wireguard(obj, wg_clients)

        dhcp_leases = self.get_dhcp_leases()
        dhcp_map = {
            lease.get('hwaddr', '').lower(): (lease.get('hostname') or '').strip()
            for lease in dhcp_leases
            if lease.get('hwaddr') and lease.get('state', '') in ('active', 'static', '')
        }

        arp_data = self.get_opnsense_arp()
        self.sync_arp_table(arp_data)
        self.sync_discovered_devices(arp_data, dhcp_map)

        self.sync_prefixes(interfaces)

        vlans = self.get_opnsense_vlans()
        self.sync_vlans(vlans)

        return "Sync Complete"

    def import_vpn_models(self):
        try:
            from vpn.models import Tunnel, TunnelGroup, TunnelTermination
            self.Tunnel = Tunnel
            self.TunnelGroup = TunnelGroup
            self.TunnelTermination = TunnelTermination
            self.TunnelEncapsulation = None
            self.vpn_available = True
            self.log_success("VPN Models imported successfully (NetBox 4.0+ Core).")
        except ImportError:
            try:
                from netbox_vpn_plugin.models import Tunnel, TunnelGroup, TunnelTermination, TunnelEncapsulation
                self.Tunnel = Tunnel
                self.TunnelGroup = TunnelGroup
                self.TunnelTermination = TunnelTermination
                self.TunnelEncapsulation = TunnelEncapsulation
                self.vpn_available = True
                self.log_success("NetBox VPN Plugin models imported successfully.")
            except ImportError:
                self.vpn_available = False

    def get_opnsense_interfaces(self):
        try:
            resp_names = self.sess.get(f"{self.opnsense_url}/api/diagnostics/interface/getInterfaceNames")
            resp_names.raise_for_status()
            names_map = resp_names.json()

            stats_url = f"{self.opnsense_url}/api/diagnostics/interface/getInterfaceStats"
            resp_stats = self.sess.get(stats_url)

            stats_map = {}
            if resp_stats.status_code == 200:
                stats_map = resp_stats.json()

            if not stats_map:
                self.log_info("Stats map empty. Trying getInterfaceConfig...")
                config_url = f"{self.opnsense_url}/api/diagnostics/interface/getInterfaceConfig"
                try:
                    resp_config = self.sess.get(config_url)
                    if resp_config.status_code == 200:
                        data = resp_config.json()
                        if isinstance(data, dict) and 'rows' in data:
                            stats_map = {row.get('identifier'): row for row in data['rows']}
                        else:
                            stats_map = data
                except Exception as e:
                    self.log_warning(f"getInterfaceConfig failed: {e}")

            stats_by_device = {}
            for key, val in stats_map.items():
                if isinstance(val, dict):
                    dev = val.get('device')
                    if dev:
                        stats_by_device[dev] = val

            interfaces = []
            for name_key, name_val in names_map.items():
                phys_name = name_key
                descr = name_val

                prefixes = ['vtnet', 'em', 'igb', 'ix', 'vmx', 're', 'lo', 'enc', 'wg', 'vlan']
                is_val_phys = name_val in stats_by_device or any(name_val.startswith(p) for p in prefixes)
                is_key_phys = name_key in stats_by_device or any(name_key.startswith(p) for p in prefixes)

                if is_val_phys and not is_key_phys:
                    phys_name = name_val
                    descr = name_key

                iface_data = {
                    'device': phys_name,
                    'description': descr,
                    'ipv4': [],
                    'macaddr': None
                }

                stat = stats_by_device.get(phys_name)
                if not stat:
                    candidates = [descr, descr.lower(), name_key, name_key.lower()]
                    for cand in candidates:
                        if cand in stats_map:
                            stat = stats_map[cand]
                            break

                if stat:
                    if 'macaddr' in stat:
                        iface_data['macaddr'] = stat['macaddr']
                    elif 'ether' in stat:
                        iface_data['macaddr'] = stat['ether']

                    if 'ipv4' in stat and isinstance(stat['ipv4'], list):
                        for ip_entry in stat['ipv4']:
                            if 'ipaddr' in ip_entry and 'subnetbits' in ip_entry:
                                iface_data['ipv4'].append({
                                    'ipaddr': ip_entry['ipaddr'],
                                    'mask': str(ip_entry['subnetbits'])
                                })

                    if 'inet' in stat and isinstance(stat['inet'], list):
                        for ip_entry in stat['inet']:
                            if 'address' in ip_entry and 'netmask' in ip_entry:
                                try:
                                    mask = ip_entry['netmask']
                                    if isinstance(mask, str) and mask.startswith('0x'):
                                        mask_int = int(mask, 16)
                                        mask = str(ipaddress.IPv4Address(mask_int))

                                    net = ipaddress.IPv4Network(f"REDACTED_IP/{mask}")
                                    prefix_len = net.prefixlen

                                    iface_data['ipv4'].append({
                                        'ipaddr': ip_entry['address'],
                                        'mask': str(prefix_len)
                                    })
                                except Exception:
                                    pass
                else:
                    self.log_info(f"No stats found for {phys_name} ({descr})")

                interfaces.append(iface_data)

            self.log_success(f"Found {len(interfaces)} interfaces.")
            return interfaces

        except Exception as e:
            self.log_failure(f"Interface sync failed: {e}")
            return []

    def get_wireguard_clients(self):
        try:
            resp = self.sess.get(f"{self.opnsense_url}/api/wireguard/client/searchClient")
            if resp.status_code == 200:
                return resp.json().get('rows', [])
            resp = self.sess.get(f"{self.opnsense_url}/api/wireguard/server/searchServer")
            if resp.status_code == 200:
                return resp.json().get('rows', [])
        except Exception as e:
            self.log_info(f"WireGuard sync skipped: {e}")
        return []

    def get_opnsense_arp(self):
        try:
            resp = self.sess.get(f"{self.opnsense_url}/api/diagnostics/interface/getArp")
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            self.log_failure(f"Error fetching ARP: {e}")
            return []

    def get_dhcp_leases(self):
        try:
            resp = self.sess.get(f"{self.opnsense_url}/api/dhcpv4/leases/searchLease")
            if resp.status_code == 200:
                return resp.json().get('rows', [])
        except Exception as e:
            self.log_info(f"DHCP lease fetch skipped: {e}")
        return []

    def get_opnsense_vlans(self):
        try:
            resp = self.sess.get(f"{self.opnsense_url}/api/interfaces/vlan_settings/searchItem")
            resp.raise_for_status()
            return resp.json().get('rows', [])
        except Exception as e:
            self.log_failure(f"Error fetching VLANs: {e}")
            return []

    def sync_object(self):
        if self.is_vm:
            vm = VirtualMachine.objects.filter(name=self.device_name).first()
            if not vm:
                vm = VirtualMachine.objects.filter(name__iexact=self.device_name).first()

            if not vm:
                self.log_failure(f"Virtual Machine '{self.device_name}' not found!")
                return None
            self.log_success(f"Found Virtual Machine: {vm.name}")
            return vm
        else:
            device = Device.objects.filter(name=self.device_name).first()
            if not device:
                device = Device.objects.filter(name__iexact=self.device_name).first()

            if not device:
                self.log_info(f"Device {self.device_name} not found. Creating...")

                role = DeviceRole.objects.filter(slug="firewall").first()
                if not role:
                    role = DeviceRole.objects.create(name="Firewall", slug="firewall", color="ff0000")

                dtype = DeviceType.objects.filter(slug="opnsense-vm").first()
                if not dtype:
                    manufacturer = Manufacturer.objects.filter(slug="opnsense").first()
                    if not manufacturer:
                        manufacturer = Manufacturer.objects.create(name="OPNsense", slug="opnsense")
                    dtype = DeviceType.objects.create(
                        manufacturer=manufacturer,
                        model="OPNsense VM",
                        slug="opnsense-vm",
                        u_height=0
                    )

                site = Site.objects.filter(slug=self.site_slug).first()
                if not site:
                    self.log_failure(f"Site '{self.site_slug}' not found!")
                    return None

                device = Device.objects.create(
                    name=self.device_name,
                    device_type=dtype,
                    role=role,
                    site=site,
                    status="active"
                )
            self.log_success(f"Found/Created Device: {device.name}")
            return device

    def sync_interfaces(self, nb_obj, opn_interfaces):
        self.log_info(f"Syncing {len(opn_interfaces)} interfaces...")

        if isinstance(nb_obj, VirtualMachine):
            InterfaceModel = VMInterface
            filter_kwargs = {'virtual_machine': nb_obj}
            assigned_object_type = ContentType.objects.get_for_model(VMInterface)
        else:
            InterfaceModel = Interface
            filter_kwargs = {'device': nb_obj}
            assigned_object_type = ContentType.objects.get_for_model(Interface)

        for iface in opn_interfaces:
            if_name = iface.get('device')
            if not if_name: continue

            if_descr = iface.get('description', '')
            mac_addr = iface.get('macaddr')

            nb_iface = None

            # 1. Try to find by MAC Address first
            # Skip MAC matching for VLAN/sub-interfaces — they share the parent's MAC
            is_vlan_iface = if_name.startswith('vlan') or '.' in if_name
            if mac_addr and not is_vlan_iface:
                try:
                    mac_obj = MACAddress.objects.filter(mac_address=mac_addr).first()
                    if mac_obj and mac_obj.assigned_object:
                        if isinstance(nb_obj, VirtualMachine) and isinstance(mac_obj.assigned_object, VMInterface):
                            if mac_obj.assigned_object.virtual_machine == nb_obj:
                                nb_iface = mac_obj.assigned_object
                        elif isinstance(nb_obj, Device) and isinstance(mac_obj.assigned_object, Interface):
                            if mac_obj.assigned_object.device == nb_obj:
                                nb_iface = mac_obj.assigned_object
                except Exception:
                    pass

            # 2. Fall back to name matching
            if not nb_iface:
                nb_iface = InterfaceModel.objects.filter(name=if_name, **filter_kwargs).first()

            if not nb_iface:
                self.log_success(f"Creating interface {if_name}")
                nb_iface = InterfaceModel.objects.create(
                    name=if_name,
                    description=if_descr,
                    **filter_kwargs
                )
            else:
                if nb_iface.name != if_name:
                    self.log_info(f"Renaming interface {nb_iface.name} to {if_name} (matched by MAC)")
                    nb_iface.name = if_name

                if nb_iface.description != if_descr:
                    nb_iface.description = if_descr

                nb_iface.save()

            if mac_addr and not is_vlan_iface:
                try:
                    mac_obj, created = MACAddress.objects.update_or_create(
                        assigned_object_type=assigned_object_type,
                        assigned_object_id=nb_iface.pk,
                        defaults={'mac_address': mac_addr}
                    )
                    if created:
                        self.log_success(f"Assigned MAC {mac_addr} to {if_name}")
                except Exception as e:
                    self.log_failure(f"Error syncing MAC for {if_name}: {e}")

            ips_to_sync = []

            if iface.get('ipaddr') and iface.get('mask'):
                ips_to_sync.append(f"{iface.get('ipaddr')}/{iface.get('mask')}")

            ipv4_list = iface.get('ipv4', [])
            if isinstance(ipv4_list, list):
                for ip_info in ipv4_list:
                    if isinstance(ip_info, str): ips_to_sync.append(ip_info)
                    elif isinstance(ip_info, dict):
                        ips_to_sync.append(f"{ip_info.get('ipaddr')}/{ip_info.get('mask')}")

            for cidr in ips_to_sync:
                self.sync_ip(nb_iface, cidr)

    def sync_wireguard(self, nb_obj, wg_clients):
        if not wg_clients: return
        self.log_info(f"Syncing {len(wg_clients)} WireGuard tunnels...")

        if isinstance(nb_obj, VirtualMachine):
            InterfaceModel = VMInterface
            filter_kwargs = {'virtual_machine': nb_obj}
        else:
            InterfaceModel = Interface
            filter_kwargs = {'device': nb_obj}

        tunnel_group = None
        encap_obj = None

        if self.vpn_available:
            tunnel_group, _ = self.TunnelGroup.objects.get_or_create(
                slug="wireguard",
                defaults={"name": "WireGuard"}
            )

            if self.TunnelEncapsulation:
                encap_obj, _ = self.TunnelEncapsulation.objects.get_or_create(
                    slug="wireguard",
                    defaults={"name": "WireGuard"}
                )

        for client in wg_clients:
            name = client.get('name', 'WG-Tunnel')
            tunnel_ip = client.get('tunneladdress') or client.get('tunnel_address', '')
            endpoint = client.get('serveraddress') or client.get('endpoint_address') or client.get('endpoint', '')

            if_name = f"wg-{name}"

            nb_iface = InterfaceModel.objects.filter(name=if_name, **filter_kwargs).first()
            if not nb_iface:
                self.log_success(f"Creating VPN interface {if_name}")
                nb_iface = InterfaceModel.objects.create(
                    name=if_name,
                    description=f"WireGuard: {name} ({endpoint})" if endpoint else f"WireGuard: {name}",
                    **filter_kwargs
                )

            if tunnel_ip:
                for ip in tunnel_ip.split(','):
                    self.sync_ip(nb_iface, ip.strip())

            if self.vpn_available and tunnel_group:
                tunnel_name = f"WG-{name}"
                tunnel = self.Tunnel.objects.filter(name=tunnel_name, group=tunnel_group).first()
                if not tunnel:
                    self.log_success(f"Creating Tunnel {tunnel_name}")

                    tunnel_defaults = {
                        "group": tunnel_group,
                        "status": "active",
                        "description": f"WireGuard Tunnel to {name}"
                    }

                    if self.TunnelEncapsulation:
                        tunnel_defaults["encapsulation"] = encap_obj
                    else:
                        tunnel_defaults["encapsulation"] = "wireguard"

                    tunnel = self.Tunnel.objects.create(
                        name=tunnel_name,
                        **tunnel_defaults
                    )

                term = self.TunnelTermination.objects.filter(tunnel=tunnel, role="peer").first()

                outside_ip_obj = None
                if endpoint:
                    try:
                        cidr = f"{endpoint}/32" if '/' not in endpoint else endpoint
                        outside_ip_obj = IPAddress.objects.filter(address=cidr).first()
                        if not outside_ip_obj:
                            self.log_success(f"Creating Outside IP {cidr}")
                            outside_ip_obj = IPAddress.objects.create(
                                address=cidr,
                                status="active",
                                description=f"WireGuard Endpoint for {name}"
                            )
                    except Exception as e:
                        self.log_failure(f"Error resolving outside IP {endpoint}: {e}")

                if not term:
                    if isinstance(nb_iface, Interface):
                        ct = ContentType.objects.get_for_model(Interface)
                    elif isinstance(nb_iface, VMInterface):
                        ct = ContentType.objects.get_for_model(VMInterface)
                    else:
                        continue

                    if self.TunnelTermination.objects.filter(termination_type=ct, termination_id=nb_iface.pk).exists():
                        continue

                    try:
                        term = self.TunnelTermination(
                            tunnel=tunnel,
                            role="peer",
                            termination_type=ct,
                            termination_id=nb_iface.pk
                        )
                        if outside_ip_obj and hasattr(term, 'outside_ip'):
                            term.outside_ip = outside_ip_obj

                        term.save()
                        self.log_success(f"Terminated Tunnel {tunnel_name} on {if_name}")
                    except Exception as e:
                        self.log_failure(f"Failed to terminate tunnel: {e}")

                elif outside_ip_obj and hasattr(term, 'outside_ip') and term.outside_ip != outside_ip_obj:
                    try:
                        term.outside_ip = outside_ip_obj
                        term.save()
                        self.log_success(f"Updated Tunnel Termination outside IP to {outside_ip_obj.address}")
                    except Exception as e:
                        self.log_failure(f"Failed to update outside IP: {e}")

    def sync_ip(self, nb_iface, cidr):
        try:
            nb_ip = IPAddress.objects.filter(address=cidr).first()
            if not nb_ip:
                self.log_success(f"Creating IP {cidr}")
                nb_ip = IPAddress.objects.create(
                    address=cidr,
                    status="active",
                    assigned_object_type=None,
                    assigned_object_id=None
                )
                nb_ip.assigned_object = nb_iface
                nb_ip.save()
            elif nb_ip.assigned_object_id != nb_iface.id:
                self.log_info(f"Re-assigning IP {cidr} to {nb_iface.name}")
                nb_ip.assigned_object = nb_iface
                nb_ip.save()
        except Exception as e:
            self.log_failure(f"Error syncing IP {cidr}: {e}")

    def sync_arp_table(self, arp_data):
        self.log_info(f"Processing {len(arp_data)} ARP entries...")

        for entry in arp_data:
            mac = entry.get('mac')
            ip = entry.get('ip')

            if not mac or not ip: continue
            mac = mac.lower()

            mac_obj = MACAddress.objects.filter(mac_address=mac).first()
            target_iface = None

            if mac_obj and mac_obj.assigned_object:
                target_iface = mac_obj.assigned_object

            if target_iface:
                nb_ips = IPAddress.objects.filter(address__istartswith=f"{ip}/")

                for nb_ip in nb_ips:
                    if nb_ip.assigned_object_id != target_iface.id:
                        self.log_success(f"ARP Discovery: Assigning {nb_ip.address} to {target_iface.name}")
                        nb_ip.assigned_object = target_iface
                        nb_ip.save()

    def sync_discovered_devices(self, arp_data, dhcp_map=None):
        self.log_info(f"Discovering connected devices from {len(arp_data)} ARP entries...")

        site = Site.objects.filter(slug=self.site_slug).first()
        if not site:
            self.log_warning("Site not found, skipping device discovery.")
            return

        role, _ = DeviceRole.objects.get_or_create(
            slug="discovered",
            defaults={"name": "Discovered", "color": "9e9e9e"}
        )
        manufacturer, _ = Manufacturer.objects.get_or_create(
            slug="unknown",
            defaults={"name": "Unknown"}
        )
        dtype, _ = DeviceType.objects.get_or_create(
            slug="generic-device",
            defaults={"manufacturer": manufacturer, "model": "Generic Device", "u_height": 0}
        )
        iface_ct = ContentType.objects.get_for_model(Interface)

        for entry in arp_data:
            mac = entry.get('mac')
            ip = entry.get('ip')
            if not mac or not ip:
                continue
            mac = mac.lower()

            # Skip MACs already assigned to a known interface
            mac_obj = MACAddress.objects.filter(mac_address=mac).first()
            if mac_obj and mac_obj.assigned_object:
                continue

            dhcp_hostname = (dhcp_map or {}).get(mac, '')
            arp_hostname = (entry.get('hostname') or '').strip()
            hostname = dhcp_hostname or arp_hostname
            device_name = hostname if hostname and hostname != '?' else f"device-{mac.replace(':', '')}"

            device = Device.objects.filter(name=device_name, site=site).first()
            if not device:
                device = Device.objects.create(
                    name=device_name,
                    device_type=dtype,
                    role=role,
                    site=site,
                    status="active"
                )
                self.log_success(f"Discovered device: {device_name} ({mac}, {ip})")

            iface = Interface.objects.filter(device=device, name="eth0").first()
            if not iface:
                iface = Interface.objects.create(device=device, name="eth0", type="other")

            mac_obj, created = MACAddress.objects.get_or_create(
                mac_address=mac,
                defaults={"assigned_object_type": iface_ct, "assigned_object_id": iface.pk}
            )
            if created:
                self.log_success(f"Assigned MAC {mac} to {device_name}")

            self.sync_ip(iface, f"{ip}/32")

    def sync_prefixes(self, interfaces):
        self.log_info("Syncing prefixes from interface IPs...")

        site = Site.objects.filter(slug=self.site_slug).first()

        # NetBox 4.x replaced the direct site FK with a generic scope field
        try:
            prefix_supports_site = isinstance(Prefix._meta.get_field('site'), DjangoFK)
        except Exception:
            prefix_supports_site = False

        seen = set()

        for iface in interfaces:
            for ip_info in iface.get('ipv4', []):
                try:
                    ipaddr = ip_info.get('ipaddr')
                    mask = ip_info.get('mask')
                    if not ipaddr or not mask:
                        continue
                    network = ipaddress.IPv4Network(f"{ipaddr}/{mask}", strict=False)
                    if network.prefixlen == 32 or str(network) in seen:
                        continue
                    seen.add(str(network))

                    qs = Prefix.objects.filter(prefix=str(network))
                    if site and prefix_supports_site:
                        qs = qs.filter(site=site)
                    if not qs.exists():
                        kwargs = {"prefix": str(network), "status": "active"}
                        if site and prefix_supports_site:
                            kwargs["site"] = site
                        Prefix.objects.create(**kwargs)
                        self.log_success(f"Created prefix {network}")
                except Exception as e:
                    self.log_warning(f"Could not derive prefix from {ip_info}: {e}")

    def sync_vlans(self, vlans):
        self.log_info(f"Syncing {len(vlans)} VLANs...")

        site = Site.objects.filter(slug=self.site_slug).first()

        try:
            vlan_supports_site = isinstance(VLAN._meta.get_field('site'), DjangoFK)
        except Exception:
            vlan_supports_site = False

        for vlan_data in vlans:
            tag = vlan_data.get('tag') or vlan_data.get('vlan')
            if not tag:
                continue
            try:
                vid = int(tag)
            except (ValueError, TypeError):
                continue

            descr = (vlan_data.get('descr') or vlan_data.get('description') or '').strip()
            name = descr if descr else f"VLAN{vid}"

            qs = VLAN.objects.filter(vid=vid)
            if site and vlan_supports_site:
                qs = qs.filter(site=site)
            vlan_obj = qs.first()

            if not vlan_obj:
                kwargs = {"vid": vid, "name": name, "status": "active"}
                if site and vlan_supports_site:
                    kwargs["site"] = site
                VLAN.objects.create(**kwargs)
                self.log_success(f"Created VLAN {vid} ({name})")
            elif vlan_obj.name != name:
                vlan_obj.name = name
                vlan_obj.save()
                self.log_info(f"Updated VLAN {vid} name to {name}")
