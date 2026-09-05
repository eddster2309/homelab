terraform {
  required_providers {
    proxmox = {
      source = "Telmate/proxmox"
      version = "3.0.1-rc9"
    }
  }

  backend "s3" {}
}

provider "proxmox" {
  pm_api_url = "https://${ var.proxmox_host }"

  pm_api_token_id = "${ var.proxmox_user }"
  pm_api_token_secret = "${ var.proxmox_password }"
  pm_tls_insecure = true
}

resource "proxmox_vm_qemu" "pihole" {
  count = var.vm_count
  name = "${format("${ var.service_name }%02s", count.index+1)}"
  desc = "${ var.service_name } - Managed by Terraform"
  tags =  count.index == 0 ? "ans-${ var.service_name },ans-${var.service_name}-primary${ var.tags }" : "ans-${ var.service_name },ans-${ var.service_name}-secondary${ var.tags }"
  onboot = true

  target_node = "${var.proxmox_node_name}"

  agent = 1

  cpu {
    cores = var.vm_cpu_core_count
  }
  
  memory = var.vm_memory

  network {
    id = 0
    firewall = false
    link_down = false
    model = "e1000"
    bridge = "${ var.vm_net_bridge }"
  }

  disks {
    ide {
      ide3 {
        cloudinit {
          storage = "${ var.proxmox_datastore_id }"
        }
      }
    }
    virtio {
      virtio0 {
        disk {
          size = "${ var.vm_disk_size }"
          storage = "${ var.proxmox_datastore_id }"
        }
      }
    }
  }
  clone = "${ var.vm_template_id }"

  os_type = "cloud-init"
  ipconfig0 = "${format("ip=%s/%s,gw=%s",cidrhost("${var.vm_network_subnet}/${var.vm_network_mask}", var.vm_start_ip + count.index), var.vm_network_mask, var.vm_ip_gateway)}"

  #ssh_user = "${ var.vm_user }"
  #sshkeys = <<EOF
  #${ var.vm_user_ssh_key }
  #EOF

}
