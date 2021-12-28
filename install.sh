#!/bin/bash
# Script modified by Yoru
# Illegal selling and redistribution of this script is strictly prohibited
# Please respect author's Property
# Binigay sainyo ng libre, ipamahagi nyo rin ng libre.

########################
# Variables

MyScriptName="Yoru's"

SSH_Banner='https://pastebin.com/raw/wiBpTFcv'

Stunnel_Port1='443'

OpenVPN_TCP_Port='110'

OvpnDownload_Port='81'

GIST="https://gist.githubusercontent.com/excelsiorcode/08de95a5728ee6302edbec6f683775d5/raw/"

MyVPS_Time='Asia/Manila' # server local time
########################

########################
function InstUpdates(){
 export DEBIAN_FRONTEND=noninteractive
 apt update -y 2>/dev/null 
 apt upgrade -y 2>/dev/null
 
 apt autoremove --fix-missing -y > /dev/null 2>&1
 apt remove --purge apache* ufw -y > /dev/null 2>&1
 
 if [[ "$(command -v firewall-cmd)" ]]; then
  apt remove --purge firewalld -y
  apt autoremove -y -f
 fi

 apt install iptables-persistent -y -f
 systemctl restart netfilter-persistent &>/dev/null
 systemctl enable netfilter-persistent &>/dev/null
 
 apt install nano wget curl zip unzip openssl dos2unix screen -y 2>/dev/null

 apt install dropbear stunnel4 python ca-certificates nginx ruby apt-transport-https lsb-release git build-essential libssl-dev libnss3-dev cmake screenfetch -y 2>/dev/null

 apt autoremove --fix-missing -y > /dev/null 2>&1

 rm -rf /etc/apt/sources.list.d/openvpn*
 echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" > /etc/apt/sources.list.d/openvpn.list
 wget -qO - http://build.openvpn.net/debian/openvpn/stable/pubkey.gpg|apt-key add -
  
 echo -e "0 4 * * * root reboot" > /etc/cron.d/b_reboot_job
 echo -e "0 */4 * * * root /usr/bin/screen -S delexpuser -dm bash -c '/usr/local/sbin/delete_expired'" > /etc/cron.d/autodelete_expusr

 systemctl restart cron
 systemctl enable cron
 
 apt update 2>/dev/null
 apt install openvpn -y &> /dev/null
 apt autoremove --fix-missing -y &>/dev/null
 apt clean 2>/dev/null
}

function InstDropbear(){

 rm -f /etc/banner
 wget -qO /etc/banner "$SSH_Banner"
 dos2unix -q /etc/banner

sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password && sed -i 's|use_authtok ||g' /etc/pam.d/common-password
 
 cat <<'MyDropbear' > /etc/default/dropbear
# disabled because OpenSSH is installed                              
# change to NO_START=0 to enable Dropbear                            
NO_START=0                                                           
# the TCP port that Dropbear listens on                              
DROPBEAR_PORT=550                                                    

# any additional arguments for Dropbear                              
DROPBEAR_EXTRA_ARGS=                                                 

# specify an optional banner file containing a message to be         
# sent to clients before they connect, such as "/etc/banner"      
DROPBEAR_BANNER="/etc/banner"                                                   

# RSA hostkey file (default: /etc/dropbear/dropbear_rsa_host_key)    
#DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"               
# DSS hostkey file (default: /etc/dropbear/dropbear_dss_host_key)    
#DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"               

# ECDSA hostkey file (default: /etc/dropbear/dropbear_ecdsa_host_key)
#DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"           

# Receive window size - this is a tradeoff between memory and        
# network performance                                                
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear

systemctl restart dropbear
}

function InsStunnel(){
 if [[ ! "$(command -v stunnel4)" ]]; then
 StunnelDir='stunnel'
 else
 StunnelDir='stunnel4'
fi

cat <<'MyStunnelD' > /etc/default/$StunnelDir
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
BANNER="/etc/banner"
PPP_RESTART=0
# RLIMITS="-n 4096 -d unlimited"
RLIMITS=""
MyStunnelD

 # Removing all stunnel folder contents
 rm -rf /etc/stunnel/*
 
 # Creating stunnel certifcate using openssl
 openssl req -new -x509 -days 9999 -nodes -subj "/C=PH/ST=NCR/L=Manila/O=Github/CN=RSA Domain Validation Secure Server CA" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem &> /dev/null

 # Creating stunnel server config
 cat <<'MyStunnelC' > /etc/stunnel/stunnel.conf
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[stunnel]
accept = Stunnel_Port1
connect = 127.0.0.1:80
MyStunnelC

 sed -i "s|Stunnel_Port1|$Stunnel_Port1|g" /etc/stunnel/stunnel.conf
 
 systemctl restart $StunnelDir
}

function InsOpenVPN(){
if [[ ! -e /etc/openvpn ]]; then
 mkdir -p /etc/openvpn
else
 rm -rf /etc/openvpn/*
fi

mkdir -p /etc/openvpn/server
mkdir -p /etc/openvpn/client

cat <<'EOFovpn1' > /etc/openvpn/server/server_tcp.conf
port 110
dev tun
proto tcp
ca /etc/openvpn/client/ca.crt
cert /etc/openvpn/client/excelsiorcode.crt
key /etc/openvpn/client/excelsiorcode.key
dh /etc/openvpn/client/dh.pem
persist-tun
persist-key
persist-remote-ip
duplicate-cn
cipher none
ncp-disable
auth none
comp-lzo
tun-mtu 1500
reneg-sec 0
plugin PLUGIN_AUTH_PAM login
verify-client-cert none
username-as-common-name
max-clients 4080
topology subnet
server 172.29.0.0 255.255.240.0
push "redirect-gateway def1"
keepalive 5 30
status /etc/openvpn/tcp_stats.log
log /etc/openvpn/tcp.log
verb 2
script-security 2
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
push "dhcp-option DNS 1.0.0.1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 8.8.8.8"
EOFovpn1

mkdir /etc/openvpn/XScript-easyrsa

curl -4skL "https://raw.githubusercontent.com/excelsiorcode/XScript/master/XScript-easyrsa.zip" -o /etc/openvpn/XScript-easyrsa/rsa.zip 2> /dev/null

unzip -qq /etc/openvpn/XScript-easyrsa/rsa.zip -d /etc/openvpn/XScript-easyrsa

rm -f /etc/openvpn/XScript-easyrsa/rsa.zip

cd /etc/openvpn/XScript-easyrsa
chmod +x easyrsa
./easyrsa build-server-full server nopass &> /dev/null
cp pki/ca.crt /etc/openvpn/client/ca.crt
cp pki/dh.pem /etc/openvpn/client/dh.pem
cp pki/issued/server.crt /etc/openvpn/client/excelsiorcode.crt
cp pki/private/server.key /etc/openvpn/client/excelsiorcode.key

cd ~/ && echo '' > /var/log/syslog

wget -qO /etc/openvpn/b.zip 'https://raw.githubusercontent.com/excelsiorcode/XScript/master/openvpn_plugin64'
unzip -qq /etc/openvpn/b.zip -d /etc/openvpn
rm -f /etc/openvpn/b.zip

sed -i "s|PLUGIN_AUTH_PAM|/etc/openvpn/openvpn-auth-pam.so|g" /etc/openvpn/server/*.conf

sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.conf
sed -i '/#net.ipv4.ip_forward.*/d' /etc/sysctl.conf
sed -i '/net.ipv4.ip_forward.*/d' /etc/sysctl.d/*
sed -i '/#net.ipv4.ip_forward.*/d' /etc/sysctl.d/*
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/20-openvpn.conf
sysctl --system &> /dev/null

 echo 1 > /proc/sys/net/ipv4/ip_forward

if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
 sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
 systemctl daemon-reload
fi

systemctl daemon-reload
systemctl restart openvpn-server &> /dev/null
systemctl start openvpn-server@server_tcp &> /dev/null
systemctl enable openvpn-server@server_tcp &> /dev/null
}
 
 function OvpnConfigs(){
 # Creating nginx config for our ovpn config downloads webserver
 cat <<'myNginxC' > /etc/nginx/conf.d/yoru-ovpn-config.conf
# My OpenVPN Config Download Directory
server {
 listen 0.0.0.0:myNginx;
 server_name localhost;
 root /var/www/openvpn;
 index index.html;
}
myNginxC

 # Setting our nginx config port for .ovpn download site
 sed -i "s|myNginx|$OvpnDownload_Port|g" /etc/nginx/conf.d/yoru-ovpn-config.conf

 # Removing Default nginx page(port 80)
 rm -rf /etc/nginx/sites-*

 # Creating our root directory for all of our .ovpn configs
 rm -rf /var/www/openvpn
 mkdir -p /var/www/openvpn

cat <<EOF15> /var/www/openvpn/OVPNWS.ovpn
# STRICTLY NO TORRENTING & OTHER ILLEGAL ACTIVITIES!
# Server Location: OPENVPN_SERVER_LOCATION
# Server ISP: OPENVPN_SERVER_ISP
# excelsiorcodeâ„¢

client
dev tun
persist-tun
proto tcp
remote $IPADDR $OpenVPN_TCP_Port
persist-remote-ip
resolv-retry infinite
connect-retry 0 1
remote-cert-tls server
nobind
reneg-sec 0
keysize 0
rcvbuf 0
sndbuf 0
verb 2
comp-lzo
auth none
auth-nocache
cipher none
setenv CLIENT_CERT 0
auth-user-pass

<ca>
$(cat /etc/openvpn/client/ca.crt)
</ca>
EOF15

sed -i "s|OPENVPN_SERVER_VERSION|$(openvpn --version | cut -d" " -f2 | head -n1)|g" /var/www/openvpn/*.ovpn
sed -i "s|OPENVPN_SERVER_LOCATION|$(curl -4s http://ipinfo.io/country), $(curl -4s http://ipinfo.io/region)|g" /var/www/openvpn/*.ovpn
sed -i "s|OPENVPN_SERVER_ISP|$(curl -4s http://ipinfo.io/org | sed -e 's/[^ ]* //')|g" /var/www/openvpn/*.ovpn

 # Creating OVPN download site index.html
cat <<'mySiteOvpn' > /var/www/openvpn/index.html
<!DOCTYPE html>
<html lang="en">

<!-- Simple OVPN Download site -->

<head><meta charset="utf-8" /><title>MyScriptName OVPN Config Download</title><meta name="description" content="Yoru Server" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="https://openvpn.net/wp-content/uploads/openvpn.jpg" class="card-img-top"><div class="mask rgba-white-slight"></div></div><div class="center"><div class="card"><div class="card-body"><h5 class="card-title"><style>.center{text-align:center;border: 2px solid green;}</style>Config List</h5><br /><ul class="list-group"><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;border: 1px solid black;"><p>For Globe/Tm <span class="badge light-blue darken-4">Android/IOS/Modem</span><br /><small> OpenVPN Websocket</small></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://IP-ADDRESS:NGINXPORT/OVPNWS.ovpn" style="float:right;"><i class="fa fa-download"></i> </a></li></ul></div></div></div></div></body></html>
mySiteOvpn
 
 # Setting template's correct name,IP address and nginx Port
 sed -i "s|MyScriptName|$MyScriptName|g" /var/www/openvpn/index.html
 sed -i "s|NGINXPORT|$OvpnDownload_Port|g" /var/www/openvpn/index.html
 sed -i "s|IP-ADDRESS|$IPADDR|g" /var/www/openvpn/index.html

 # Restarting nginx service
 systemctl restart nginx
 
 # Creating all .ovpn config archives
 cd /var/www/openvpn
 zip -qq -r Configs.zip *.ovpn
 cd
}

function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
} 
IPADDR="$(ip_address)"


function ConfStartup(){
if [[ ! -e /etc/yoru ]]; then
 mkdir -p /etc/yoru
fi
cat <<'EOFSH' > /etc/yoru/startup.sh
#!/bin/bash

export DEBIAN_FRONTEND=noninteractive

screen -S delexpuser -dm bash -c "/usr/local/sbin/delete_expired" &>/dev/null
EOFSH

 chmod +x /etc/yoru/startup.sh
 
 rm -rf /etc/sysctl.d/99*

echo 'clear' > /etc/profile.d/yoru.sh
echo 'screenfetch -p | sed -r "/^\s*$/d"' >> /etc/profile.d/yoru.sh
echo 'echo -e ""' >> /etc/profile.d/yoru.sh
echo 'echo -e " Type menu"' >> /etc/profile.d/yoru.sh
echo 'echo -e ""' >> /etc/profile.d/yoru.sh
echo 'echo -e " For non-root users:"' >> /etc/profile.d/yoru.sh
echo 'echo -e " Always \e[1;38;5;231msudo su -\e[0m before executing commands!"' >> /etc/profile.d/yoru.sh
echo 'echo -e ""' >> /etc/profile.d/yoru.sh

 chmod +x /etc/profile.d/yoru.sh
 
curl -skL "$GIST/sshws.service" -o /lib/systemd/system/sshws.service
curl -skL "$GIST/ovpnws.service" -o /lib/systemd/system/ovpnws.service
curl -skL "$GIST/sshws.py" -o /usr/local/bin/sshws.py
curl -skL "$GIST/ovpnws.py" -o /usr/local/bin/ovpnws.py

 chmod +x /lib/systemd/system/sshws.service
 chmod +x /lib/systemd/system/ovpnws.service
 chmod +x /usr/local/bin/sshws.py
 chmod +x /usr/local/bin/ovpnws.py
 
systemctl daemon-reload
systemctl enable sshws.service  &> /dev/null
systemctl enable ovpnws.service  &> /dev/null
systemctl start sshws.service
systemctl start ovpnws.service

echo "[Unit]
Description=Yoru Startup Script
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/yoru/startup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/YorusVPN.service
 
 chmod +x /etc/systemd/system/YorusVPN.service
 
systemctl daemon-reload
systemctl start YorusVPN
systemctl enable YorusVPN &> /dev/null
}

function InsAIP(){
printf "%b\n" "\e[1;37mConfiguring Iptables Setup...\e[0m"
cat <<'iptEOF'> /tmp/iptables-config.bash
#!/bin/bash
IPADDR="$(curl -4sk http://ipinfo.io/ip)"
PNET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
CIDR="172.29.0.0/16"
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X
iptables -A INPUT -s $IPADDR -p tcp -m multiport --dport 1:65535 -j ACCEPT
iptables -A INPUT -s $IPADDR -p udp -m multiport --dport 1:65535 -j ACCEPT
iptables -A INPUT -p tcp --dport 25 -j REJECT   
iptables -A FORWARD -p tcp --dport 25 -j REJECT
iptables -A OUTPUT -p tcp --dport 25 -j REJECT
iptables -I FORWARD -s $CIDR -j ACCEPT
iptables -t nat -A POSTROUTING -s $CIDR -o $PNET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $CIDR -o $PNET -j SNAT --to-source $IPADDR
iptables-save > /etc/iptables/rules.v4
iptEOF
screen -S configIptables -dm bash -c "bash /tmp/iptables-config.bash && rm -f /tmp/iptables-config.bash"
}

function InstBadVPN(){
printf "%b\n" "\e[1;37mrunning BadVPN-udpgw installation...\e[0m"
if [[ -e /usr/local/bin/badvpn-udpgw ]]; then
 printf "%s\n" "BadVPN-udpgw is already installed"
 exit 1
fi
    curl -skL "https://www.dropbox.com/s/ubsgol6b8t2s2hm/badvpn-udpgw" -o /usr/local/bin/badvpn-udpgw 
	chmod +x /usr/local/bin/badvpn-udpgw
	curl -skL "https://gist.githubusercontent.com/excelsiorcode/3b259ca177ef4ba78145ee8d360b8fc5/raw/badvpn-udpgw.service" -o /lib/systemd/system/badvpn-udpgw.service
	systemctl daemon-reload
	systemctl enable badvpn-udpgw &> /dev/null
	systemctl start badvpn-udpgw
}
 
function ConfMenu(){
echo -e "\e[1;37mCreating Menu scripts...\e[0m"

cd /usr/local/sbin/
rm -rf {accounts,base-script,clearcache,connected_users,create,create_random,create_trial,customize,delete_expired,exit,locked_list,menu,returnws,user_delete,user_details,user_details_lib,user_extend,user_list,user_lock,user_unlock}
wget -q 'https://raw.githubusercontent.com/excelsiorcode/websocket/master/menu.zip'
unzip -qq menu.zip
rm -f menu.zip
chmod +x ./*
dos2unix ./* &> /dev/null

cd ~
}

function ScriptMessage(){
 echo -e ""
 echo -e " â˜… $MyScriptName SSH/SSL/OVPN WS AutoScript â˜…"
 echo -e ""
 }

function UnAll(){
 echo -e ""
 echo -e "Removing Dropbear"
 systemctl stop dropbear
 apt remove --purge dropbear -y
 rm -rf /etc/default/dropbear
 rm -rf /etc/dropbear/*
 echo -e "Removing stunnel"
 systemctl stop stunnel &> /dev/null
 systemctl stop stunnel4 &> /dev/null
 apt remove --purge stunnel -y
 rm -rf /etc/stunnel/*
 rm -rf /etc/default/stunnel*
 rm -rf /usr/local/bin/sshws*
 systemctl stop sshws
 rm -rf /lib/systemd/system/sshws*
 echo -e "Removing OpenVPN server and BadVPN"
 systemctl stop openvpn-server@server_tcp &>/dev/null
 apt remove --purge openvpn -y -f
 rm -rf /etc/openvpn/*
 rm -rf /var/www/openvpn
 rm -rf /etc/apt/sources.list.d/openvpn*
 systemctl disable openvpn-server@server_tcp &>/dev/null
 rm -rf /etc/nginx/conf.d/yoru-ovpn-config*
 systemctl restart nginx &> /dev/null
 rm -rf /usr/local/{share/man/man7/badvpn*,share/man/man8/badvpn*,bin/badvpn-*}
 systemctl stop badvpn-udpgw
 rm -rf /lib/systemd/system/badvpn-udpgw*
 rm -rf /usr/local/bin/ovpnws*
 systemctl stop ovpnws
 rm -rf /lib/systemd/system/ovpnws*
 echo -e "Finalizing.."
 rm -rf /etc/yoru
 rm -rf /etc/banner
 systemctl stop YorusVPN &> /dev/null
 rm -rf /etc/systemd/system/YorusVPN*
 systemctl disable YorusVPN &> /dev/null
 rm -rf /etc/cron.d/b_reboot_job
 systemctl restart cron &> /dev/null
 rm -rf /usr/local/sbin/{accounts,base-ports,base-ports-wc,base-script,bench-network,clearcache,connectedusers,create,create_random,create_trial,delete_expired,delete_all,diagnose,edit_dropbear,edit_openssh,edit_openvpn,edit_ports,edit_squid,edit_stunnel,exit,locked_list,menu,options,ram,reboot_sys,reboot_sys_auto,restart_services,screenfetch,server,set_multilogin_autokill,set_multilogin_autokill_lib,show_ports,speedtest,user_delete,user_details,user_details_lib,user_extend,user_list,user_lock,user_unlock}
 rm -rf /etc/profile.d/yoru.sh
 rm -rf /tmp/*
 apt autoremove -y -f
 echo 3 > /proc/sys/vm/drop_caches
}

#############################

## Installation Process
## WARNING: Do not modify or edit anything
## if you didn't know what to do.
## This part is too sensitive.

#############################

function InstScript(){
 # Now check if our machine is in root user, if not, this script exits
 # If you're on sudo user, run `sudo su -` first before running this script
 if [[ $EUID -ne 0 ]];then
 echo -e ""
 echo -e "[\e[1;31mError\e[0m] This script must be run as root."
 exit 1
fi

 # (For OpenVPN) Checking it this machine have TUN Module, this is the tunneling interface of OpenVPN server
 if [[ ! -e /dev/net/tun ]]; then
 echo -e ""
 echo -e "[\e[1;31mÃ—\e[0m] You can't use this script without TUN Module installed/embedded in your machine, file a support ticket to your machine admin about this matter"
 exit 1
fi

 # Begin Installation by Updating and Upgrading machine and then Installing all our wanted packages/services to be install.
 echo -e ""
 echo -e ""
 sleep 2
 
 echo -e "\e[1;37mUpdating System...\e[0m"
 InstUpdates
 
 # Configure Dropbear
 echo -e "\e[1;37mConfiguring Dropbear...\e[0m"
 InstDropbear

 # Configure Dropbear
 echo -e "\e[1;37mConfiguring OpenSSH...\e[0m"
  
 # Configure Stunnel
 echo -e "\e[1;37mConfiguring Stunnel...\e[0m"
 InsStunnel

 # Configure OpenVPN
 echo -e "\e[1;37mConfiguring OpenVPN...\e[0m"
 InsOpenVPN
 InsAIP
 InstBadVPN

 # Configuring Nginx OVPN config download site
 OvpnConfigs

 # VPS Menu script
 ConfMenu

 # Some assistance and startup scripts
 ConfStartup

 # Setting server local time
 ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime
 sed -i '/\/bin\/false/d' /etc/shells
 sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
 echo '/bin/false' >> /etc/shells
 echo '/usr/sbin/nologin' >> /etc/shells
 sleep 1
 #######
 
 clear
 clear
 clear

 # Running sysinfo 
 bash /etc/profile.d/yoru.sh
 
 # Showing script's banner message
 ScriptMessage
 
 # Showing additional information from installating this script
 echo -e ""
 echo -e " Success Installation!"
 echo -e ""
 echo -e "\e[92m Service Ports\e[0m"
 echo -e ""
 echo -e "\e[92m SSH Websocket\e[0m\e[97m: 80\e[0m"
 echo -e "\e[92m SSL Websocket\e[0m\e[97m: $Stunnel_Port1\e[0m"
 echo -e "\e[92m OpenVPN Websocket\e[0m\e[97m: 8880\e[0m"
 echo -e "\e[92m NGiNX\e[0m\e[97m: $OvpnDownload_Port\e[0m"
 echo -e "\e[92m BadVPN-udpgw\e[0m\e[97m: 7300\e[0m"
 echo -e ""
 echo -e ""
 echo -e "\e[92m OpenVPN Websocket Download Site\e[0m\e[97m:\e[0m"
 echo -e "\e[97m http://$IPADDR:$OvpnDownload_Port\e[0m"
 echo -e ""
 echo -e " Message me @ https://t.me/vlr_exile"
 echo -e " Â©excelsiorcode"
 echo -e ""
 echo -e "[\e[92m Note \e[0m]\e[97m DO NOT RESELL THIS SCRIPT\e[0m"
 
 # Clearing all logs from installation
 rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog
 rm -f install*
}

case $1 in
 install)
 ScriptMessage
 InstScript
 exit 1
 ;;
 uninstall|remove)
 ScriptMessage
 UnAll
 clear
 ScriptMessage
 echo -e ""
 echo -e "   Uninstallation complete."
 echo -e ""
 rm -f install*
 exit 1
 ;;
 help|--help|-h)
 ScriptMessage
 echo -e " install = Install script"
 echo -e " uninstall = Remove all services installed by this script"
 echo -e " help = show this help message"
 exit 1
 ;;
 *)
 clear
 ScriptMessage
 echo -e "   CTRL + C if you want to cancel it."
 sleep 3
 InstScript
 exit 1
  ;;
esac
