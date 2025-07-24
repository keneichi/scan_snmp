#!/usr/bin/env python3
import nmap
from pysnmp.hlapi import *
import csv
import socket

# Réseaux à scanner
NETWORKS = ["192.168.10.0/24","192.168.70.0/24"]

# Community strings à tester
COMMUNITIES = ["public", "private", "4X8NVSa"]

# Fichier de sortie
OUTPUT_FILE = "snmp_report.csv"

# Timeout pour SNMP
SNMP_TIMEOUT = 0.5  # secondes


def discover_snmp_hosts(network):
    print(f"[*] Scan nmap sur {network} (UDP 161)...")
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sU -p161 --open')
    hosts = nm.all_hosts()
    print(f"[+] {len(hosts)} hôte(s) SNMP détecté(s) sur {network}")
    return hosts


def snmp_get(ip, community, oid):
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=0),
        UdpTransportTarget((ip, 161), timeout=SNMP_TIMEOUT, retries=0),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication or errorStatus:
        return None
    for varBind in varBinds:
        return str(varBind[1])


def test_communities(ip):
    for community in COMMUNITIES:
        sysdescr = snmp_get(ip, community, '1.3.6.1.2.1.1.1.0')  # sysDescr.0
        if sysdescr:
            sysname = snmp_get(ip, community, '1.3.6.1.2.1.1.5.0') or "N/A"
            return community, sysname, sysdescr
    return None, None, None


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "N/A"

def main():
    for network in NETWORKS:
        print(f"\n=== Scan du réseau {network} ===")
        hosts = discover_snmp_hosts(network)
        results = []

        for ip in hosts:
            hostname = reverse_dns(ip)
            print(f"[*] Test SNMP sur {ip} ({hostname})...")
            community, sysname, sysdescr = test_communities(ip)
            if community:
                print(f"[+] {ip} ({hostname}) - SNMP OK (community: {community}, sysName: {sysname})")
                results.append((ip, hostname, sysname, sysdescr, community))
            else:
                print(f"[-] {ip} ({hostname}) - SNMP actif mais community inconnue")
                results.append((ip, hostname, "N/A", "N/A", "inconnue"))

        # On génère un nom de fichier basé sur le sous-réseau
        filename = f"snmp_report_{network.replace('/', '_')}.csv"
        with open(filename, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Hostname", "sysName", "sysDescr", "Community"])
            writer.writerows(results)

        print(f"[+] Rapport généré : {filename}")

if __name__ == "__main__":
    main()
