#!/bin/bash
#

# This script gathers evidence files from Linux systems

# IMPORTANT: This script must be run with root privileges

if [ $EUID -ne 0 ]; then
	echo "This script must be run as root. Please try again using a user account with root privileges."
	exit 1
fi

# Fail if too many arguments are entered
if [ $# != 0 ]; then
	echo "Too many arguments."
	echo "Usage: ./linux-script.sh"
	exit 1
fi

# Create evidence directory
timeStamp=`date +%m-%d-%y_%H%M%S`
outfile=$HOSTNAME"_"$timeStamp
if [ -d /tmp ]; then
	mkdir /tmp/$outfile
else
	mkdir /tmp
	mkdir /tmp/$outfile
fi
cd /tmp/$outfile

echo "Please wait while the server configurations for $HOSTNAME are gathered. This may take a few moments and system output may be displayed while the script is running. This script has finished executing when the user prompt reappears. Please upload the output file /tmp/$outfile.tar.bz2 to https://portal.sunera.com/sfu/ and notify Sunera with the names of the uploaded file(s) via email."

# Catch errors
exec 2> debug.log

# File check and copy function

if_exists_then_copy() {
	local file=$1
	new_file=$(basename $file)
	if [ -f $file ]
	then
		cp --backup=numbered $file $new_file-$HOSTNAME.txt
	else
		echo "$file not found. Please provide an alternative file if applicable." >> debug.log
	fi
}
# Determine OS
if [ -f /etc/redhat-release ]
then
    OS='redhat'
    cat /etc/redhat-release > distro_version-$HOSTNAME.txt
fi

# Hostname
hostname > hostname-$HOSTNAME.txt
dnsdomainname > dnsdomainname-$HOSTNAME.txt

# Interfaces
ifconfig > ifconfig-$HOSTNAME.txt

# Traceroute
traceroute 8.8.8.8 > traceroute-$HOSTNAME.txt

# System information
uname -a > uname-$HOSTNAME.txt

# Netstat information
netstat -nlp > netstat-listeners-$HOSTNAME.txt
netstat -r > netstat-route-$HOSTNAME.txt

# Processes
ps aux > psaux-$HOSTNAME.txt
service --status-all > service_status_all_$HOSTNAME.txt

# List installed packages
rpm -qa > rpmqa-$HOSTNAME.txt
cp /var/log/yum.log yum_log-$HOSTNAME.txt
yum check-update > yum_updates-$HOSTNAME.txt
yum --security check-update > yum_security_updates-$HOSTNAME.txt

# List services
chkconfig --list > chkconfig-$HOSTNAME.txt
sysv-rc-conf --list > sysv-rc-conf-$HOSTNAME.txt

# Copy configuration files
if_exists_then_copy /etc/ssh/sshd_config
if_exists_then_copy /etc/sudoers
if_exists_then_copy /etc/ntp.conf
ls -l /etc/ntp.conf > ntp-permissions-$HOSTNAME.txt
ls -l /var/log > log_file_permissions-$HOSTNAME.txt
if_exists_then_copy /var/lib/ntp/drift
if_exists_then_copy /etc/nsswitch.conf
if_exists_then_copy /etc/login.defs
if_exists_then_copy /etc/profile
if_exists_then_copy /etc/issue
if_exists_then_copy /etc/*-release
if_exists_then_copy /etc/rsyslog.conf
if_exists_then_copy /etc/snmp/snmpd.conf
if_exists_then_copy /etc/audit/audit.conf
if_exists_then_copy /etc/audit/audit.rules
if_exists_then_copy /etc/opt/quest/vas/vas.conf
if_exists_then_copy /etc/shadow
if_exists_then_copy /etc/group
if_exists_then_copy /etc/passwd

# 081115 ISACA Auditing Additions

#Protect Grub Using Passwords
if_exists_then_copy /boot/grub/menu.lst
if_exists_then_copy /boot/grub/grub.conf

#Auditing Disk Partitioning in the Audited System
#Check filesystems on hard disk
fdisk -l

#Auditing SSH Passwordless Login
#Check file used to store preshared SSH keys
if_exists_then_copy ~/.ssh/authorized_keys

#Auditing the Status of USB Devices
#Check file used to restrict automount of USB using 'mount -a' or at boot
if_exists_then_copy /etc/fstab
#Check for USB kernel modules
grep -R "usb-storage.ko" /lib/modules > usb-storage_modules-$HOSTNAME.txt
#Check module blacklist for USB kernel modules
if_exists_then_copy /etc/modprobe.d/blacklist.conf

#Auditing the Status of SELinux
SELINUX_ENABLED=`cat /selinux/enforce`
if [ "$SELINUX_ENABLED" == 1 ]
then
echo "SELinux is enabled" > selinux_status-$HOSTNAME.txt
elif [ "$SELINUX_DISABLED" == 0 ]
then
echo "SELinux is disabled" > selinux_status-$HOSTNAME.txt
else
echo "Command not found" > selinux_status-$HOSTNAME.txt
fi

#Auditing the IPv6 Status
if_exists_then_copy /etc/sysconfig/network

#Auditing Internet Control Message Protocol or Broadcast Request
if_exists_then_copy /etc/sysctl.conf

#Auditing the Configuration of the NTP Server
ntpq -p > ntp_sync-$HOSTNAME.txt
ntpstat > ntp_status-$HOSTNAME.txt

# Check for virtualization
dmidecode > virtual_check-$HOSTNAME.txt
if_exists_then_copy /proc/scsi/scsi


if [ -f /opt/quest/bin/vastool ]
then
    /opt/quest/bin/vastool info servers > vastool_servers-$HOSTNAME.txt
    /opt/quest/bin/vastool list users-allowed > vastool_users-$HOSTNAME.txt
else
    echo "The system is not running Quest" > vastool_servers-$HOSTNAME.txt
fi

cp -R /etc/pam.d/ ./
mv pam.d pam.d-$HOSTNAME 

# Cron jobs
mkdir cron-$HOSTNAME
cp -R /etc/cron.* cron-$HOSTNAME

for user in `cat /etc/passwd|cut -d ':' -f 1`
do
	echo "***** Crontab for $user *****" >> cron-$HOSTNAME/crontab-users-$HOSTNAME.txt
	crontab -u $user -l >> cron-$HOSTNAME/crontab-users-$HOSTNAME.txt
done

# Log output
lastlog > lastlog-$HOSTNAME.txt
tail -n 100 /var/log/messages > var_log_messages-$HOSTNAME.txt
tail -n 100 /var/log/secure > var_log_secure-$HOSTNAME.txt
tail -n 100 /var/log/utmp > var_log_utmp-$HOSTNAME.txt
tail -n 100 /var/log/wtmp > var_log_wtmp-$HOSTNAME.txt
tail -n 100 /var/log/kern.log > var_log_kern-$HOSTNAME.txt
tail -n 100 /var/log/cron.log > var_log_cron-$HOSTNAME.txt
tail -n 100 /var/log/maillog > var_log_maillog-$HOSTNAME.txt
tail -n 100 /var/log/boot.log > var_log_boot-$HOSTNAME.txt
tail -n 100 /var/log/mysqld.log > var_log_mysqld-$HOSTNAME.txt

# SNMPv3
if [ -f /var/lib/snmp/snmpd.conf ]
then
	echo "Contents of /var/lib/snmp/snmpd.conf" >> snmpv3_confs-$HOSTNAME.txt
	cat /var/lib/snmp/snmpd.conf >> snmpv3_conf-$HOSTNAME.txt
fi
if [ -f /usr/share/snmp/snmpd.conf ]
then
	echo "Contents of /usr/share/snmp/snmpd.conf" >> snmpv3_confs-$HOSTNAME.txt
	cat /usr/share/snmp/snmpd.conf >> snmpv3_conf-$HOSTNAME.txt
fi
if [ -f /var/net-snmp/snmpd.conf ]
then
	echo "Contents of /var/net-snmp/snmpd.conf" >> snmpv3_confs-$HOSTNAME.txt
	cat /var/net-snmp/snmpd.conf >> snmpv3_conf-$HOSTNAME.txt
fi

# SSH testing
logsave ssh-null-cipher-check-$HOSTNAME.txt ssh -c none -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no 127.0.0.1 > /dev/null & pid=$!
sleep 3
kill $pid

logsave ssh-version-1-check-$HOSTNAME.txt ssh -1 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no 127.0.0.1 > /dev/null & pid=$!
sleep 3
kill $pid

logsave ssh-full-conversation-$HOSTNAME.txt ssh -vv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no 127.0.0.1 > /dev/null & pid=$!
sleep 3
kill $pid

# Gather all authentication methods used

grep passwd /etc/nsswitch.conf | grep -v '^#' | cut -d ':' -f2 | sed 's/^ *//g' > authtypes-$HOSTNAME.txt

while read line
do
    for type in $line
    do
        if [ $type == 'ldap' ]
        then
            if [ $OS == 'debian' ]
            then
                cp /etc/ldap/ldap.conf ldap_conf-$HOSTNAME.txt
            elif [ $OS == 'redhat' ]
            then
                cp /etc/openldap/ldap.conf ldap_conf-$HOSTNAME.txt
            else
                cp /etc/ldap.conf ldap_conf-$HOSTNAME.txt
            fi
        elif [ $type == 'radius' ]
        then
            if [ $OS == 'debian' ] || [ $OS == 'redhat' ]
            then
                cp /etc/radiusclient/radiusclient.conf radiusclient_conf-$HOSTNAME.txt 
                cp /etc/radiusclient-ng/radiusclient.conf radiusclient-ng_conf-$HOSTNAME.txt
            elif [ $OS == 'suse' ]
            then
                cp /etc/radiusclient/radiusclient.conf radiusclient_conf-$HOSTNAME.txt
            else
                cp /etc/radius.conf radius_conf-$HOSTNAME.txt
            fi
        elif [ $type == 'tacacs' ]
        then
            cp /etc/tac_plus.conf tac_plus_conf-$HOSTNAME.txt
        elif [ $type == 'nis' ]
        then
            cp /etc/yp.conf yp_conf-$HOSTNAME.txt
        elif [ $type == 'files' ] || [ $type == 'compat' ]
        then
            cp /etc/passwd passwd-$HOSTNAME.txt
            cp /etc/shadow shadow-$HOSTNAME.txt
            cp /etc/group group-$HOSTNAME.txt

            for user in `cat /etc/passwd|cut -d ':' -f 1`
            do
                echo "***** Listing password info for $user *****" >> password-info-$HOSTNAME.txt
                chage -l $user >> password-info-$HOSTNAME.txt
                passwd -S $user >> user-status-$HOSTNAME.txt
            done
        elif [ $type == 'centrifydc' ]
        then
            cp /etc/centrifydc/centrifydc.conf centrifydc_conf-$HOSTNAME.txt
            cp /etc/centrifydc/ssh/sshd_config centrifysshd_conf-$HOSTNAME.txt
        elif [ $type == 'lsass' ]
        then
            which lwsmd

            if [ $? -eq 0 ]
            then
                lw-lsa get-status > likewise-status-$HOSTNAME.txt
            fi 
        else
            echo "Auth type $type not recognized" >> unrecognized_auth_type-$HOSTNAME.txt
        fi
    done
done <authtypes-$HOSTNAME.txt

# HTTPS ciphers
if [ -f /etc/httpd/conf.d/ssl.conf ]; then
	echo "Contents of /etc/httpd/conf.d/ssl.conf" >> ssl_confs-$HOSTNAME.txt
	cat /etc/httpd/conf.d/ssl.conf >> ssl_confs-$HOSTNAME.txt
fi
if [ -f /etc/apache2/mods-enabled/ssl.conf ]; then
	echo "Contents of /etc/apache2/mods-enabled/ssl.conf" >> ssl_confs-$HOSTNAME.txt
	cat /etc/apache2/mods-enabled/ssl.conf >> ssl_confs-$HOSTNAME.txt
fi
if [ -d /etc/apache2/vhost.d ]; then
	echo "Grep for ciphers in vhost.d" >> ssl_confs-$HOSTNAME.txt
	grep -i ciphers /etc/apache2/vhost.d/* >> ssl_confs-$HOSTNAME.txt
fi

# IPTables
iptables -L -v > iptables-$HOSTNAME.txt

# Xinetd files
if [ -d /etc/xinetd* ]; then
	mkdir xinetd-$HOSTNAME
	cp -R /etc/xinetd* xinetd-$HOSTNAME
fi

mkdir logrotate-$HOSTNAME
cp /etc/logrotate.conf logrotate-$HOSTNAME
cp -R /etc/logrotate.d/ logrotate-$HOSTNAME

# AIDE configuration
if [ -f /etc/aide ]; then
	mkdir aide-$HOSTNAME
	cp -R /etc/aide aide-$HOSTNAME
	cp /etc/aide.conf aide-$HOSTNAME
fi

# OSSEC files
if [ -d /var/ossec ]; then
	mkdir ossec-$HOSTNAME
	cp -R /var/ossec ossec-$HOSTNAME
fi

# etc files
cp -R /etc ./
mv etc etc-$HOSTNAME

# List empty files
md5sum * > md5sums-$HOSTNAME.txt
lines=( )
for line in `cat md5sums-$HOSTNAME.txt| cut -d " " -f 3`
do
	lines+=("$line")
done
lineNum=0
for line in `cat md5sums-$HOSTNAME.txt| cut -d " " -f 1`
do
	if [ "$line" = "d41d8cd98f00b204e9800998ecf8427e" ]; then
		echo ${lines[$lineNum]} >> empty-files-$HOSTNAME.txt
	fi
	lineNum=$(($lineNum + 1))
done

echo " "
echo "The following files were empty. Please provide equivalent files or the results of equivalent commands if they exist on $HOSTNAME."
cat empty-files-$HOSTNAME.txt


# Compress
cd ../
tar cfj $outfile.tar.bz2 $outfile
rm -rf $outfile
