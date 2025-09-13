# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/performing_an_advanced_rhel_installation/kickstart-commands-and-options-reference_installing-rhel-as-an-experienced-user

# Set the authentication options for the system
auth --passalgo=sha512 --useshadow
# License agreement
eula --agreed
# Use network installation
url --url="http://aarnet.repos.example.com/pub/rocky/9/BaseOS/x86_64/os/"
repo --name="AppStream" --baseurl=http://aarnet.repos.example.com/pub/rocky/9/AppStream/x86_64/os/
# Use text mode install
text
# Disable Initial Setup on first boot
firstboot --disable
# Keyboard layout
keyboard --vckeymap=us --xlayouts='us'
# System language
lang en_US.UTF-8
# Network information
network --bootproto=dhcp --device=link --activate
network --hostname=rocky9.localdomain
# SELinux configuration
selinux --enforcing
# Do not configure the X Window System
skipx
# System timezone
timezone Australia/Sydney
# Add a user named cloud-user
user --groups=wheel --name=cloud-user --password=$6$Jaa5U0EwAPMMp3.5$m29yTwr0q9ZJVJGMXvOnm9q2z13ldUFTjB1sxPHvaiW4upMSwQ50181wl7SjHjh.BTH7FGHx37wrX..SM0Bqq. --iscrypted --gecos="cloud-user" --groups='wheel,sudo'
sshkey --username=cloud-user 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEHNADnxgalkaTehfJZGi+UK33LkmBTuhdSyXFLDp6Zv jack@jp-desktop'
# System bootloader configuration
bootloader --location=mbr --append="crashkernel=auto"
# Clear the Master Boot Record
zerombr
# Remove partitions
clearpart --all --initlabel
# Automatically create partitions using LVM
autopart --type=lvm
# Reboot after successful installation
reboot

%packages --ignoremissing
# dnf group info minimal-environment
@^minimal-environment
# Exclude unnecessary firmwares
-iwl*firmware
ipa-client
cloud-init
python3-libdnf5
python3.13
cloud-utils-growpart
%end

%post --nochroot --logfile=/mnt/sysimage/root/ks-post.log
# Disable quiet boot and splash screen
sed --follow-symlinks -i "s/ rhgb quiet//" /mnt/sysimage/etc/default/grub
sed --follow-symlinks -i "s/ rhgb quiet//" /mnt/sysimage/boot/grub2/grubenv

# Passwordless sudo for the user 'packer'
echo "cloud-user ALL=(ALL) NOPASSWD: ALL" >> /mnt/sysimage/etc/sudoers.d/clouduser

systemctl enable cloud-init-local
systemctl enable cloud-init
systemctl enable cloud-config
systemctl enable cloud-final

%end