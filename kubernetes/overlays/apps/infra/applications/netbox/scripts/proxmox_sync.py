import requests
import urllib3
from django.contrib.contenttypes.models import ContentType
from extras.scripts import Script, StringVar, BooleanVar
from dcim.models import Device, DeviceRole, DeviceType, Interface, Manufacturer, Site
from ipam.models import IPAddress
from virtualization.models import Cluster, ClusterType, VirtualMachine, VMInterface
try:
    from dcim.models import MACAddress
    HAS_MAC_MODEL = True
except ImportError:
    HAS_MAC_MODEL = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SKIP_PREFIXES = ('lo', 'docker', 'br-', 'veth', 'virbr', 'flannel', 'cni', 'tunl', 'dummy')
SKIP_IPS = ('127.', '::1', 'fe80::')


def _norm_mac(mac):
    if not mac:
        return None
    return mac.strip().lower()


def _skip_iface(name):
    return any(name.startswith(p) for p in SKIP_PREFIXES)


def _skip_ip(addr):
    return any(addr.startswith(p) for p in SKIP_IPS)


class ProxmoxSyncScript(Script):
    class Meta:
        name = "Proxmox Sync"
        description = "Sync VMs and containers from Proxmox into NetBox, enriching records found by other sources"
        commit_default = True

    proxmox_url = StringVar(
        description="Proxmox API URL (e.g., https://pve.example.com:8006)",
        default="https://pve.example.com:8006"
    )
    api_token = StringVar(
        description="Proxmox API Token (format: user@realm!tokenid=secret)",
    )
    cluster_name = StringVar(
        description="Name for the Proxmox Cluster in NetBox (leave blank for standalone host — VMs will be assigned to the site directly)",
        default="",
        required=False
    )
    site_slug = StringVar(
        description="Slug of the Site in NetBox",
        default="lab"
    )
    verify_ssl = BooleanVar(
        description="Verify SSL Certificate",
        default=False
    )
    sync_lxc = BooleanVar(
        description="Also sync LXC containers",
        default=True
    )
    use_guest_agent = BooleanVar(
        description="Use QEMU guest agent for IP discovery (requires agent installed in VMs)",
        default=True
    )

    def run(self, data, commit):
        self.base_url = data['proxmox_url'].rstrip('/')
        self.verify = data['verify_ssl']
        self.cluster_name = data['cluster_name']
        self.site_slug = data['site_slug']
        self.sync_lxc = data['sync_lxc']
        self.use_guest_agent = data['use_guest_agent']

        token_str = data['api_token']
        self.sess = requests.Session()
        self.sess.verify = self.verify
        # Token format: user@realm!tokenid=secret
        if '=' in token_str:
            token_id, secret = token_str.split('=', 1)
            self.sess.headers['Authorization'] = f"PVEAPIToken={token_id}={secret}"
        else:
            self.log_failure("API token must be in format user@realm!tokenid=secret")
            return

        self.vm_iface_ct = ContentType.objects.get_for_model(VMInterface)

        site = Site.objects.filter(slug=self.site_slug).first()
        if not site:
            self.log_failure(f"Site '{self.site_slug}' not found.")
            return

        cluster = self._ensure_cluster(site) if self.cluster_name else None
        if self.cluster_name and not cluster:
            return

        nodes = self._api_get('/nodes')
        if not nodes:
            self.log_failure("Could not fetch Proxmox nodes.")
            return

        total_vms = 0
        for node in nodes:
            node_name = node['node']
            self.log_info(f"Processing node: {node_name}")

            vms = self._api_get(f'/nodes/{node_name}/qemu') or []
            for vm in vms:
                vmid = vm['vmid']
                name = vm.get('name') or f"vm-{vmid}"
                self._sync_vm(cluster, site, node_name, vmid, name, vm, is_lxc=False)
                total_vms += 1

            if self.sync_lxc:
                containers = self._api_get(f'/nodes/{node_name}/lxc') or []
                for ct in containers:
                    vmid = ct['vmid']
                    name = ct.get('name') or f"ct-{vmid}"
                    self._sync_vm(cluster, site, node_name, vmid, name, ct, is_lxc=True)
                    total_vms += 1

        self.log_success(f"Sync complete. Processed {total_vms} VMs/containers.")

    # ------------------------------------------------------------------
    # Proxmox API helpers
    # ------------------------------------------------------------------

    def _api_get(self, path, ignore_errors=False):
        try:
            resp = self.sess.get(f"{self.base_url}/api2/json{path}", timeout=15)
            resp.raise_for_status()
            return resp.json().get('data')
        except Exception as e:
            if not ignore_errors:
                self.log_warning(f"API error {path}: {e}")
            return None

    # ------------------------------------------------------------------
    # Cluster / infrastructure
    # ------------------------------------------------------------------

    def _ensure_cluster(self, site):
        cluster_type, _ = ClusterType.objects.get_or_create(
            slug="proxmox",
            defaults={"name": "Proxmox"}
        )

        cluster, created = Cluster.objects.get_or_create(
            name=self.cluster_name,
            defaults={"type": cluster_type, "site": site}
        )
        if created:
            self.log_success(f"Created cluster: {self.cluster_name}")
        else:
            changed = False
            if cluster.type != cluster_type:
                cluster.type = cluster_type
                changed = True
            # site field may be a scope in newer NetBox — try both
            try:
                if cluster.site != site:
                    cluster.site = site
                    changed = True
            except AttributeError:
                pass
            if changed:
                cluster.save()

        return cluster

    # ------------------------------------------------------------------
    # VM sync
    # ------------------------------------------------------------------

    def _sync_vm(self, cluster, site, node_name, vmid, name, pve_data, is_lxc):
        status_map = {'running': 'active', 'stopped': 'offline', 'paused': 'staged'}
        nb_status = status_map.get(pve_data.get('status', ''), 'offline')

        vcpus = int(pve_data.get('cpus', pve_data.get('maxcpu', 1)))
        memory_mb = int(pve_data.get('maxmem', 0)) // (1024 * 1024)

        # Find existing VM by name (case-insensitive), or create
        nb_vm = (
            VirtualMachine.objects.filter(name=name).first()
            or VirtualMachine.objects.filter(name__iexact=name).first()
        )

        # Always absorb any 'discovered' Device placeholder with this name,
        # whether or not the VM already exists from a prior sync
        self._absorb_discovered_device(name)

        if not nb_vm:
            create_kwargs = dict(name=name, status=nb_status, vcpus=vcpus, memory=memory_mb)
            if cluster:
                create_kwargs['cluster'] = cluster
            else:
                try:
                    create_kwargs['site'] = site
                except Exception:
                    pass
            nb_vm = VirtualMachine.objects.create(**create_kwargs)
            self.log_success(f"Created VM: {name} (vmid={vmid})")
        else:
            changed = False
            if cluster and nb_vm.cluster != cluster:
                nb_vm.cluster = cluster
                changed = True
            elif not cluster:
                try:
                    if nb_vm.site != site:
                        nb_vm.site = site
                        changed = True
                except AttributeError:
                    pass
            if nb_vm.status != nb_status:
                nb_vm.status = nb_status
                changed = True
            if vcpus and nb_vm.vcpus != vcpus:
                nb_vm.vcpus = vcpus
                changed = True
            if memory_mb and nb_vm.memory != memory_mb:
                nb_vm.memory = memory_mb
                changed = True
            if changed:
                nb_vm.save()
                self.log_info(f"Updated VM: {name}")

        # Sync network interfaces
        if is_lxc:
            self._sync_lxc_ifaces(nb_vm, node_name, vmid)
        else:
            self._sync_qemu_ifaces(nb_vm, node_name, vmid)

    # ------------------------------------------------------------------
    # Interface sync — QEMU VMs
    # ------------------------------------------------------------------

    def _sync_qemu_ifaces(self, nb_vm, node_name, vmid):
        config = self._api_get(f'/nodes/{node_name}/qemu/{vmid}/config', ignore_errors=True)
        if not config:
            return

        # Parse net* keys from config to get MAC addresses
        config_macs = {}  # iface_name -> mac
        for key, val in config.items():
            if not key.startswith('net'):
                continue
            # val looks like: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,...
            parts = {p.split('=')[0]: p.split('=')[1] for p in val.split(',') if '=' in p}
            mac = None
            for driver in ('virtio', 'e1000', 'vmxnet3', 'rtl8139'):
                if driver in parts:
                    mac = _norm_mac(parts[driver])
                    break
            if mac:
                iface_index = key[3:]  # net0 -> 0
                config_macs[f"eth{iface_index}"] = mac

        # Try guest agent for actual interface names and IPs
        agent_ifaces = []
        if self.use_guest_agent:
            agent_data = self._api_get(
                f'/nodes/{node_name}/qemu/{vmid}/agent/network-if',
                ignore_errors=True
            )
            if agent_data:
                agent_ifaces = agent_data.get('result', []) or []

        if agent_ifaces:
            self._apply_agent_ifaces(nb_vm, agent_ifaces)
        else:
            # Fallback: create interfaces from config MACs only
            for iface_name, mac in config_macs.items():
                nb_iface = self._find_or_create_iface(nb_vm, iface_name, mac)
                # No IPs without agent
                _ = nb_iface

    # ------------------------------------------------------------------
    # Interface sync — LXC containers
    # ------------------------------------------------------------------

    def _sync_lxc_ifaces(self, nb_vm, node_name, vmid):
        config = self._api_get(f'/nodes/{node_name}/lxc/{vmid}/config', ignore_errors=True)
        if not config:
            return

        for key, val in config.items():
            if not key.startswith('net'):
                continue
            # val looks like: name=eth0,bridge=vmbr0,hwaddr=AA:BB:CC:DD:EE:FF,ip=dhcp,...
            parts = {}
            for segment in val.split(','):
                if '=' in segment:
                    k, v = segment.split('=', 1)
                    parts[k.strip()] = v.strip()

            iface_name = parts.get('name', key)
            mac = _norm_mac(parts.get('hwaddr') or parts.get('macaddr'))
            ip_cidr = parts.get('ip')
            ip6_cidr = parts.get('ip6')

            if _skip_iface(iface_name):
                continue

            nb_iface = self._find_or_create_iface(nb_vm, iface_name, mac)

            for cidr in (ip_cidr, ip6_cidr):
                if cidr and cidr not in ('dhcp', 'auto', 'manual', ''):
                    if not _skip_ip(cidr.split('/')[0]):
                        self._assign_ip(nb_iface, cidr)

    # ------------------------------------------------------------------
    # Guest agent interface application
    # ------------------------------------------------------------------

    def _apply_agent_ifaces(self, nb_vm, agent_ifaces):
        for iface in agent_ifaces:
            name = iface.get('name', '')
            if not name or _skip_iface(name):
                continue

            mac = _norm_mac(iface.get('hardware-address') or iface.get('mac-address'))
            nb_iface = self._find_or_create_iface(nb_vm, name, mac)

            for ip_entry in iface.get('ip-addresses', []):
                addr = ip_entry.get('ip-address', '')
                prefix_len = ip_entry.get('prefix', ip_entry.get('ip-address-type') and None)
                addr_type = ip_entry.get('ip-address-type', '')

                if not addr or _skip_ip(addr):
                    continue

                if prefix_len is not None:
                    cidr = f"{addr}/{prefix_len}"
                elif addr_type == 'ipv4':
                    cidr = f"{addr}/32"
                else:
                    cidr = f"{addr}/128"

                self._assign_ip(nb_iface, cidr)

    # ------------------------------------------------------------------
    # Interface helpers
    # ------------------------------------------------------------------

    def _absorb_discovered_device(self, name):
        """
        Delete a placeholder Device with role 'discovered' that matches this VM name.
        IPs are left unassigned so _assign_ip can re-attach them to the VMInterface.
        """
        try:
            device = (
                Device.objects.filter(name=name, role__slug='discovered').first()
                or Device.objects.filter(name__iexact=name, role__slug='discovered').first()
            )
            if not device:
                return
            # Detach IPs so they can be picked up by the VM interfaces
            iface_ct = ContentType.objects.get_for_model(Interface)
            IPAddress.objects.filter(
                assigned_object_type=iface_ct,
                assigned_object_id__in=device.interfaces.values_list('pk', flat=True)
            ).update(assigned_object_type=None, assigned_object_id=None)
            device.delete()
            self.log_info(f"Absorbed discovered Device placeholder: {name}")
        except Exception as e:
            self.log_warning(f"Could not absorb device placeholder '{name}': {e}")

    def _find_or_create_iface(self, nb_vm, name, mac):
        """Find an existing VMInterface by MAC or name, or create it."""
        nb_iface = None

        # 1. Try MAC match (works across renames)
        if mac and HAS_MAC_MODEL:
            mac_obj = MACAddress.objects.filter(mac_address=mac).first()
            if mac_obj and mac_obj.assigned_object:
                obj = mac_obj.assigned_object
                if isinstance(obj, VMInterface) and obj.virtual_machine == nb_vm:
                    nb_iface = obj
                elif isinstance(obj, Interface):
                    # MAC is on a Device interface (e.g. OPNsense discovery placeholder)
                    # Detach IPs so they can be re-assigned to this VMInterface below
                    iface_ct = ContentType.objects.get_for_model(Interface)
                    IPAddress.objects.filter(
                        assigned_object_type=iface_ct,
                        assigned_object_id=obj.pk
                    ).update(assigned_object_type=None, assigned_object_id=None)
                    device = obj.device
                    device_name = device.name
                    # Delete the MAC record — it will be recreated on the VMInterface
                    mac_obj.delete()
                    # If it's a discovered placeholder, delete the whole device
                    try:
                        if device.role.slug == 'discovered':
                            device.delete()
                            self.log_info(f"  Removed discovered Device placeholder: {device_name}")
                    except Exception as e:
                        self.log_warning(f"  Could not delete device {device_name}: {e}")
                    self.log_info(f"  Migrated MAC {mac} from Device/{device_name} to VM/{nb_vm.name}")

        # 2. Fall back to name match
        if not nb_iface:
            nb_iface = VMInterface.objects.filter(virtual_machine=nb_vm, name=name).first()

        if not nb_iface:
            nb_iface = VMInterface.objects.create(virtual_machine=nb_vm, name=name)
            self.log_success(f"  Created interface {nb_vm.name}/{name}")
        else:
            if nb_iface.name != name:
                self.log_info(f"  Renaming {nb_vm.name}/{nb_iface.name} -> {name} (MAC match)")
                nb_iface.name = name
                nb_iface.save()

        # Assign/update MAC
        if mac and HAS_MAC_MODEL:
            try:
                mac_obj, created = MACAddress.objects.update_or_create(
                    assigned_object_type=self.vm_iface_ct,
                    assigned_object_id=nb_iface.pk,
                    defaults={'mac_address': mac}
                )
                if created:
                    self.log_success(f"  Assigned MAC {mac} to {nb_vm.name}/{name}")
            except Exception as e:
                self.log_warning(f"  MAC assign failed for {name}: {e}")
        elif mac and not HAS_MAC_MODEL:
            # Older NetBox: mac_address field directly on VMInterface
            try:
                if nb_iface.mac_address != mac:
                    nb_iface.mac_address = mac
                    nb_iface.save()
            except Exception:
                pass

        return nb_iface

    # ------------------------------------------------------------------
    # IP helpers
    # ------------------------------------------------------------------

    def _assign_ip(self, nb_iface, cidr):
        """
        Assign an IP to a VMInterface. If the IP already exists (e.g. found
        by OPNsense ARP sync), update its assignment rather than creating a
        duplicate. Skips link-local and loopback addresses.
        """
        try:
            # Normalise — strip host bits for /32 and /128 to keep as-is
            addr_part = cidr.split('/')[0]
            if _skip_ip(addr_part):
                return

            # Look for an exact match first, then a host-only match
            nb_ip = IPAddress.objects.filter(address=cidr).first()
            if not nb_ip:
                # Try matching just the address without prefix length
                nb_ip = IPAddress.objects.filter(address__startswith=f"{addr_part}/").first()

            if nb_ip:
                if nb_ip.assigned_object_id != nb_iface.pk or nb_ip.assigned_object_type != self.vm_iface_ct:
                    self.log_info(f"  Reassigning {nb_ip.address} -> {nb_iface.virtual_machine.name}/{nb_iface.name}")
                    nb_ip.assigned_object_type = self.vm_iface_ct
                    nb_ip.assigned_object_id = nb_iface.pk
                    nb_ip.save()
            else:
                nb_ip = IPAddress.objects.create(
                    address=cidr,
                    status='active',
                    assigned_object_type=self.vm_iface_ct,
                    assigned_object_id=nb_iface.pk,
                )
                self.log_success(f"  Created IP {cidr} on {nb_iface.virtual_machine.name}/{nb_iface.name}")

        except Exception as e:
            self.log_failure(f"  IP sync error for {cidr}: {e}")
