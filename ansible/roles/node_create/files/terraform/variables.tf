// DNS managment details

variable "dns_server" {
    description = "DNS server IP address"
    type = string 
}

variable "search_domain" {
    description = "DNS search domain"
    type = string 
}

// Proxmox details

variable "proxmox_datastore_id" {
    description = "Name/ID of proxmox datastore"
    type = string
}

variable "vm_template_id" {
    description = "ID of vm template to clone"
    type = string
}

variable "proxmox_host" {
    description = "Proxmox host address (ip/domain:port) https will be appended"
    type = string 
}
variable "proxmox_password" {
    description = "Proxmox API password"
    type = string 
    sensitive = true
}
variable "proxmox_user" {
    description = "Proxmox API user"
    type = string 
}

#variable "vm_user" {
#    description = "User to create with cloud init"
#    type = string 
#}
#variable "vm_user_ssh_key" {
#    description = "User to create with cloud init"
#    type = string 
#}

variable "proxmox_node_name" {
    description = "Proxmox node name"
    type = string
}
variable "vm_count" {
    description = "Number of nodes"
    type = number 
}
variable "vm_cpu_core_count" {
    description = "VM CPU cores"
    type = number 
}

variable "vm_memory" {
    description = "VM RAM in MB"
    type = number 
}

variable "vm_disk_size" {
    description = "VM disk size in GB"
    type = string 
}

variable "vm_net_bridge" {
    description = "VM network bridge"
    type = string 
}

variable "vm_start_ip" {
    description = "VM start IP address"
    type = string 
}

variable "vm_network_mask" {
    description = "VM subnet mask"
    type = string 
}

variable "vm_ip_gateway" {
    description = "VM gateway IP address"
    type = string 
}

variable "vm_network_subnet" {
    description = "VM network subnet"
    type = string
}

variable "service_name" {
    description = "Service name"
    type = string 
}

variable "tags" {
    description = "VM Tags"
    type = string
    default = ""
}