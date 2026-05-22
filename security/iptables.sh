#!/bin/bash
modprobe ip_tables

function ClearRules(){
echo -n "Cleaning IPTABLES rules ................................... "
 # Cleaning Chains
 iptables -F INPUT
 iptables -F OUTPUT
 iptables -F FORWARD
 iptables -F -t filter
 iptables -F POSTROUTING -t nat
 iptables -F PREROUTING -t nat
 iptables -F OUTPUT -t nat
 iptables -F -t nat
 iptables -t nat -F
 iptables -t mangle -F
 iptables -X

 # Resetting counters
 iptables -Z
 iptables -t nat -Z
 iptables -t mangle -Z

 # Setting default ACCEPT policies
 iptables -P INPUT ACCEPT
 iptables -P OUTPUT ACCEPT
 iptables -P FORWARD ACCEPT
}

function EnablePing(){
 echo -n "Enabling ping response .................................... "
 echo "0" > /proc/sys/net/ipv4/icmp_echo_ignore_all
}

function DisableProtection(){
 echo -n "Removing native Operating System protections .............. "
 i=/proc/sys/net/ipv4

 echo "1" > /proc/sys/net/ipv4/ip_forward
 echo "0" > $i/tcp_syncookies
 echo "0" > $i/icmp_echo_ignore_broadcasts
 echo "0" > $i/icmp_ignore_bogus_error_responses

 for i in /proc/sys/net/ipv4/conf/*; do
   echo "1" > $i/accept_redirects
   echo "1" > $i/accept_source_route
   echo "0" > $i/log_martians
   echo "0" > $i/rp_filter
 done
}

function CleanTables(){
echo -n "Cleaning IPTABLES rules ................................... "

# Cleaning tables
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
}

function EnableProtection(){
echo -n "Enabling native Operating System protections .............. "

# Enabling basic kernel protections
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
# Enable syncookies usage (very useful against SYN flood attacks)

# To block pings to the host:
# echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all

echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
# Do not accept ICMP redirects

echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
# Enable protection against fake ICMP error messages

echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
# Prevent Smurf attacks and similar local network attacks
}

function DefaultPolicies(){
echo -n "Configuring IPTABLES default policy ....................... "

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
}

function SynPacketProtection (){
echo -n "Enabling SYN attack protection ............................ "

iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW \
-m limit --limit 5/m --limit-burst 7 \
-j LOG --log-level 4 --log-prefix "Drop Syn"

iptables -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
}

function FragmentedPacketProtection (){
echo -n "Enabling fragmented packet protection ..................... "

iptables -A INPUT -f -m limit --limit 5/m --limit-burst 7 \
-j LOG --log-level 4 --log-prefix "Fragments Packets"

iptables -A INPUT -f -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
}

function NullPacketProtection (){
echo -n "Enabling NULL packet protection ........................... "

iptables -A INPUT -p tcp --tcp-flags ALL NONE \
-m limit --limit 5/m --limit-burst 7 \
-j LOG --log-level 4 --log-prefix "NULL Packets"

iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
}

function XmasPacketProtection (){
echo -n "Enabling XMAS packet protection ........................... "

iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN \
-m limit --limit 5/m --limit-burst 7 \
-j LOG --log-level 4 --log-prefix "XMAS Packets"

iptables -A INPUT -i eth0 -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
}

function FinScanProtection (){
echo -n "Enabling FIN scan protection .............................. "

iptables -A INPUT -p tcp --tcp-flags FIN,ACK FIN \
-m limit --limit 5/m --limit-burst 7 \
-j LOG --log-level 4 --log-prefix "Fin Packets Scan"

iptables -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
}

function SmurfProtection () {
echo -n "Enabling SMURF attack protection .......................... "

iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
}

function InvalidPacketProtection () {
echo -n "Enabling invalid packet drop protection ................... "

iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
}

function RstFlagProtection () {
echo -n "Enabling RST flag rate limiting ........................... "

iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST \
-m limit --limit 2/second --limit-burst 2 -j ACCEPT
}

function PortScanProtection () {
echo -n "Enabling NMAP port scan protection ........................ "

iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m recent --set

iptables -A INPUT -p tcp -m conntrack --ctstate NEW \
-m recent --update --seconds 30 --hitcount 10 \
-j LOG --log-prefix "SCAN ATTEMPT "

iptables -A INPUT -p tcp -m conntrack --ctstate NEW \
-m recent --update --seconds 30 --hitcount 10 -j DROP

iptables -A INPUT -p tcp --tcp-flags ALL FIN,SYN -j DROP
}

function AllowLoopback(){
echo -n "Allowing loopback ......................................... "

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Maintain active sessions
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED,NEW -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED,NEW -j ACCEPT
}

function FilterTable(){
echo -n "FILTER table rules ........................................ "

#######################################
# --------- FILTER TABLE ------------ #
#######################################

# INPUT traffic
iptables -A INPUT -p tcp -s 192.168.10.1 --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -s 192.168.10.1 --dport 80 -j ACCEPT
iptables -A INPUT -p icmp -s 192.168.20.0/24 --icmp-type 8 -j ACCEPT

# INPUT DoS prevention
iptables -A INPUT -p tcp --dport 80 \
-m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# INPUT logging
iptables -A INPUT -m limit --limit 5/m --limit-burst 7 \
-j LOG --log-prefix " INPUT DROP "

iptables -A INPUT -j DROP

#######################################
# -------- OUTPUT traffic ----------- #
#######################################

iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type 8 -j ACCEPT

iptables -A OUTPUT -m limit --limit 5/m --limit-burst 7 \
-j LOG --log-prefix " OUTPUT DROP "

iptables -A OUTPUT -j DROP

#######################################
# -------- FORWARD traffic ---------- #
#######################################

iptables -A FORWARD -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -p tcp --dport 22 -d 192.168.20.4 -j ACCEPT
}

function NatTable () {
echo -n "NAT table rules ........................................... "

iptables -t nat -A PREROUTING -p tcp -d 192.168.10.3 \
--dport 80 -j DNAT --to 192.168.20.4:80

iptables -t nat -A PREROUTING -p tcp -d 192.168.10.3 \
--dport 4444 -j DNAT --to 192.168.20.4:22
}

function MangleTable (){
echo -n "MANGLE table rules ........................................ "
}

#######################################
# -------- FUNCTION CALLS ----------- #
#######################################

function StartFirewall(){

echo -e "\033[01;31m==========================================================="
echo -e "| \033[01;32mIPTABLES FIREWALL\033[01;31m ______ \033[01;32mCREATED BY: CRENATOVB\033[01;31m |"
echo -e "\033[01;31m===========================================================\033[01;37m"
echo -e ""

if CleanTables
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m ERROR \033[01;37m]"
 fi

if EnableProtection
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m ERROR \033[01;37m]"
 fi

if DefaultPolicies
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m ERROR \033[01;37m]"
 fi

if SmurfProtection
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m ERROR \033[01;37m]"
 fi

if SynPacketProtection
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m ERROR \033[01;37m]"
 fi

if AllowLoopback
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m ERROR \033[01;37m]"
 fi

if FilterTable
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m ERROR \033[01;37m]"
 fi

if NatTable
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m ERROR \033[01;37m]"
 fi
}

function StopFirewall(){

echo -e "\033[01;31m==========================================================="
echo -e "| \033[01;32mIPTABLES FIREWALL\033[01;31m ______ \033[01;32mCREATED BY: CRENATOVB\033[01;31m |"
echo -e "\033[01;31m===========================================================\033[01;37m"
echo -e ""

if ClearRules
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m ERROR \033[01;37m]"
fi

if EnablePing
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m ERROR \033[01;37m]"
 fi

if DisableProtection
  then
   echo -e "[\033[01;32m  OK  \033[01;37m]"
  else
   echo -e "[\033[01;31m ERROR \033[01;37m]"
 fi

 echo
}

case $1 in
  start)
   StartFirewall
   exit 0
  ;;

  stop)
   StopFirewall
  ;;

  *)
   echo "Choose a valid option { start | stop }"
   echo
esac
