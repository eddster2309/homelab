# Packer VM Images
This directory contains various [Packer](https://www.packer.io/) build scripts for [Proxmox](https://www.proxmox.com/en/products/proxmox-virtual-environment/overview) VM templates that I use in my Homelab.

## How to use
1. Create a `credentials.pkr.hcl` file within this directory using the example file.
2. Run the following from within the image you want to build:
```bash
packer build -var-file=../credentials.pkr.hcl packer.pkr.hcl
```
