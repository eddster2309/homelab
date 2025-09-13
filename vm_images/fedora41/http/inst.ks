#version=Fedora 41
#documentation: https://docs.fedoraproject.org/en-US/fedora/f36/install-guide/appendixes/Kickstart_Syntax_Reference/

# PRE-INSTALLATION SCRIPT
%pre --interpreter=/usr/bin/bash --log=/root/anaconda-ks-pre.log
%end

# INSTALL USING TEXT MODE
text

# KEYBOARDS, LANGUAGES, TIMEZONE
keyboard --vckeymap=us --xlayouts=us
lang en_US.UTF-8
timezone Australia/Sydney --utc

# NETWORK, SELINUX, FIREWALL
network --device=link --bootproto=dhcp --onboot=on --noipv6 --activate
selinux --enforcing
firewall --enabled --ssh

zerombr
clearpart --all --initlabel
bootloader
autopart
# INSTALLATION SOURCE, EXTRA REPOSITOROIES, PACKAGE GROUPS, PACKAGES
url --url="http://aarnet.repos.example.com/pub/fedora/linux/releases/41/Everything/x86_64/os"
repo --name=fedora-updates --baseurl="http://aarnet.repos.example.com/pub/fedora/linux/updates/41/Everything/x86_64" --cost=0
repo --name=fedora-cisco-openh264 --baseurl="http://fedora-codecs.repos.example.com/openh264/41/x86_64/os" --install
repo --name=rpmfusion-free --baseurl="http://rpmfusion.repos.example.com/free/fedora/releases/41/Everything/x86_64/os"
repo --name=rpmfusion-free-updates --baseurl="http://rpmfusion.repos.example.com/rpmfusion/free/fedora/updates/41/x86_64" --cost=0
repo --name=rpmfusion-nonfree --baseurl="http://rpmfusion.repos.example.com/rpmfusion/nonfree/fedora/releases/41/Everything/x86_64/os"
repo --name=rpmfusion-nonfree-updates --baseurl="http://rpmfusion.repos.example.com/rpmfusion/nonfree/fedora/updates/41/x86_64" --cost=0
# Extras repository is needed to install `epel-release` package.
# Remove `@guest-agents` group if this is not a VM.
%packages --retries=5 --timeout=20 --inst-langs=en
@guest-agents
kernel-devel
openssh-server
cloud-init
ipa-client
qemu-guest-agent
nano
vim
nfs-utils
python3-libdnf5
python3.13
cloud-utils-growpart
%end

# GROUPS, USERS, ENABLE SSH, FINISH INSTALL
rootpw --lock
# Create user 'myuser' and group 'mygroup' (with GID 3000), make it myuser's primary group, and add myuser to administrative 'wheel' group.
user --name=cloud-user --plaintext --gecos='Cloud User' --groups='wheel,sudo' --gid=3000
sshkey --username=cloud-user 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCVpWvlhccLn1FkIlXaJZ6x0uXdWfV0b52ctZWITUjN8ysfX1qaTfn//YC4OVBjueiM0hpdMiz+ciVOUhm30OLohz88VXek9AznRJdlRaHg0Dxwdx6pxJmkkSGOx2aSVUbTn4D81yhpcYrEnnezFGUMWkdP7d2DLXC4BBkQgWFBoX0JD/v8oqgjJL7RobJrpeMbJgreFkGtmyj/FAeoajxXGMtKqqCgN37in8qwkoYFCvyOgUNOedrG6B9mDpgLLGudqpzuVnGIcH7YghdWqeLqWDleGFLam7d8v67O3vvHSS+na2N/XnSFkbV/ps6brMGm/XRD47tyLJf2L6UCXIpc8K6g60IeOy0yl4j+CMN1LIGj1bYsKv6lCNuLDeqJOBIA0SZyz+x5ljgbjE0xe8mTcfk5xg1iIv/w4cW/wIhWTGgFoGW2cFiKY214kMHtnFndBXwEidg7O2KM7mBJchaF9ec8GCfkGHtVfyZFVy11n6FWe28fenAY27FtqPeYK9k= jack@devbox'
services --enabled='sshd.service'
reboot --eject

# ENABLE EMERGENCY KERNEL DUMPS FOR DEBUGGING
%addon com_redhat_kdump --reserve-mb=auto --enable
%end

# POST-INSTALLATION SCRIPT
%post --interpreter=/usr/bin/bash --log=/root/anaconda-ks-post.log --erroronfail
# Enable CodeReady Builder repo (requires `epel-release` package).
/usr/bin/dnf config-manager --set-enabled crb

install \
    -o root -g root -m400 \
    <(echo -e '%cloud-user\tALL=(ALL)\tNOPASSWD: ALL') \
    /etc/sudoers.d/freewheelers
%end
