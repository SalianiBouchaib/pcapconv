import streamlit as st
import pandas as pd
from scapy.all import rdpcap, Packet, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Auth, Dot11AssoReq, Dot11AssoResp, Dot11ProbeReq, Dot11ProbeResp, Dot11Deauth, Dot11Disas, Dot11QoS, RadioTap, Dot11CCMP, Dot11TKIP
from scapy.layers.eap import EAPOL
import io
from datetime import datetime
import binascii
import re

def safe_str(value):
    """Convert any value to a safe string for CSV - handles Scapy objects and escapes special chars"""
    if value is None or value == '':
        return ''
    
    # Handle Scapy FlagValue objects
    if hasattr(value, '__class__') and 'FlagValue' in str(value.__class__):
        try:
            return str(value. value) if hasattr(value, 'value') else str(int(value))
        except:
            pass
    
    # Handle other Scapy field objects
    if hasattr(value, '__class__') and hasattr(value.__class__, '__module__'):
        if 'scapy' in value.__class__.__module__:
            try:
                return str(int(value))
            except: 
                try:
                    return str(value)
                except:
                    return ''
    
    # Regular conversion
    try:
        if isinstance(value, (int, float)):
            return str(value)
        result = str(value)
        
        # Remove problematic characters that can break CSV
        result = result.replace('\n', ' ').replace('\r', ' ').replace('\x00', '')
        
        # Remove other non-printable characters
        result = ''.join(char if char.isprintable() or char in [' ', '\t'] else '' for char in result)
        
        return result
    except:
        return ''

def extract_packet_info(packet):
    """Extract EVERYTHING from a packet"""
    packet_info = {
        'timestamp': datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S. %f'),
        'length': len(packet),
        'protocol':  '',
        
        # MAC addresses
        'src_mac': '',
        'dst_mac': '',
        'bssid': '',
        'addr4': '',
        
        # IP layer
        'src_ip': '',
        'dst_ip': '',
        'ip_version': '',
        'ip_tos': '',
        'ip_id': '',
        'ttl': '',
        'ip_flags': '',
        'ip_frag_offset': '',
        
        # TCP/UDP
        'src_port':  '',
        'dst_port':  '',
        'tcp_flags': '',
        'tcp_seq': '',
        'tcp_ack': '',
        'tcp_window': '',
        'udp_length': '',
        
        # Checksums
        'checksum': '',
        
        # Payload
        'payload_size': '',
        'payload_hex': '',
        
        # Packet structure
        'layer_count': len(packet. layers()),
        'highest_layer': packet.lastlayer().name if hasattr(packet, 'lastlayer') else '',
        'all_layers': '',
        
        # WiFi RadioTap fields
        'radiotap_version': '',
        'radiotap_length': '',
        'signal_strength': '',
        'data_rate': '',
        'channel_freq': '',
        'channel_flags': '',
        'antenna':  '',
        'rx_flags': '',
        
        # WiFi 802.11 fields
        'wifi_type': '',
        'wifi_subtype': '',
        'wifi_type_subtype_name': '',
        'frame_control': '',
        'duration': '',
        'sequence_number': '',
        'fragment_number': '',
        'flags_to_ds': '',
        'flags_from_ds': '',
        'flags_more_frag': '',
        'flags_retry': '',
        'flags_power_mgmt': '',
        'flags_more_data': '',
        'flags_protected': '',
        'flags_order': '',
        
        # WiFi network info
        'ssid': '',
        'supported_rates': '',
        'channel': '',
        'encryption': '',
        'rsn_version': '',
        'group_cipher': '',
        'pairwise_ciphers': '',
        'auth_suites': '',
        'capabilities': '',
        'vendor_specific': '',
        
        # WiFi management
        'beacon_interval': '',
        'listen_interval': '',
        'current_ap': '',
        'reason_code': '',
        'status_code': '',
        'auth_algorithm': '',
        'auth_seq': '',
        
        # QoS
        'qos_tid': '',
        'qos_eosp': '',
        'qos_ack_policy': '',
        
        # Security
        'wep_iv': '',
        'wep_keyid': '',
        'tkip_tsc': '',
        'ccmp_pn': '',
        
        # General info
        'info': '',
        'summary': '',
    }
    
    try:
        # Get all layers
        layer_names = []
        layer = packet
        while layer:
            layer_names.append(layer.name)
            layer = layer.payload if hasattr(layer, 'payload') and layer.payload else None
        packet_info['all_layers'] = ' / '.join(layer_names)
        
        # RadioTap layer
        if packet.haslayer(RadioTap):
            radiotap = packet[RadioTap]
            packet_info['protocol'] = 'RadioTap'
            packet_info['radiotap_version'] = safe_str(getattr(radiotap, 'version', ''))
            packet_info['radiotap_length'] = safe_str(getattr(radiotap, 'len', ''))
            
            if hasattr(radiotap, 'dBm_AntSignal'):
                packet_info['signal_strength'] = f"{safe_str(radiotap. dBm_AntSignal)} dBm"
            elif hasattr(radiotap, 'AntSignal'):
                packet_info['signal_strength'] = safe_str(radiotap.AntSignal)
            
            if hasattr(radiotap, 'Rate'):
                try:
                    rate = float(radiotap.Rate) / 2
                    packet_info['data_rate'] = f"{rate} Mbps"
                except:
                    packet_info['data_rate'] = safe_str(radiotap.Rate)
            
            if hasattr(radiotap, 'ChannelFrequency'):
                packet_info['channel_freq'] = f"{safe_str(radiotap. ChannelFrequency)} MHz"
            if hasattr(radiotap, 'ChannelFlags'):
                packet_info['channel_flags'] = safe_str(radiotap.ChannelFlags)
            
            if hasattr(radiotap, 'Antenna'):
                packet_info['antenna'] = safe_str(radiotap. Antenna)
            
            if hasattr(radiotap, 'RXFlags'):
                packet_info['rx_flags'] = safe_str(radiotap.RXFlags)
        
        # Dot11 layer
        if packet.haslayer(Dot11):
            dot11 = packet[Dot11]
            
            frame_types = {0: 'Management', 1: 'Control', 2: 'Data', 3: 'Reserved'}
            
            frame_subtypes = {
                (0, 0): 'Association Request', (0, 1): 'Association Response',
                (0, 2): 'Reassociation Request', (0, 3): 'Reassociation Response',
                (0, 4): 'Probe Request', (0, 5): 'Probe Response',
                (0, 8): 'Beacon', (0, 9): 'ATIM', (0, 10): 'Disassociation',
                (0, 11): 'Authentication', (0, 12): 'Deauthentication', (0, 13): 'Action',
                (1, 8): 'Block Ack Request', (1, 9): 'Block Ack', (1, 10): 'PS-Poll',
                (1, 11): 'RTS', (1, 12): 'CTS', (1, 13): 'ACK',
                (1, 14): 'CF-End', (1, 15): 'CF-End + CF-Ack',
                (2, 0): 'Data', (2, 1): 'Data + CF-Ack', (2, 2): 'Data + CF-Poll',
                (2, 3): 'Data + CF-Ack + CF-Poll', (2, 4): 'Null', (2, 5): 'CF-Ack',
                (2, 6): 'CF-Poll', (2, 7): 'CF-Ack + CF-Poll', (2, 8): 'QoS Data',
                (2, 12): 'QoS Null',
            }
            
            dot11_type = int(dot11.type) if hasattr(dot11, 'type') else 0
            dot11_subtype = int(dot11.subtype) if hasattr(dot11, 'subtype') else 0
            
            packet_info['wifi_type'] = frame_types.get(dot11_type, f'Type {dot11_type}')
            packet_info['wifi_subtype'] = str(dot11_subtype)
            packet_info['wifi_type_subtype_name'] = frame_subtypes.get((dot11_type, dot11_subtype), f'Unknown ({dot11_type},{dot11_subtype})')
            
            if hasattr(dot11, 'FCfield'):
                try:
                    fc_val = int(dot11.FCfield)
                    packet_info['frame_control'] = hex(fc_val)
                except:
                    packet_info['frame_control'] = safe_str(dot11.FCfield)
            
            packet_info['dst_mac'] = safe_str(getattr(dot11, 'addr1', ''))
            packet_info['src_mac'] = safe_str(getattr(dot11, 'addr2', ''))
            packet_info['bssid'] = safe_str(getattr(dot11, 'addr3', ''))
            if hasattr(dot11, 'addr4') and dot11.addr4:
                packet_info['addr4'] = safe_str(dot11.addr4)
            
            if hasattr(dot11, 'SC'):
                try:
                    sc_val = int(dot11.SC)
                    packet_info['sequence_number'] = str(sc_val >> 4)
                    packet_info['fragment_number'] = str(sc_val & 0xF)
                except:
                    pass
            
            if hasattr(dot11, 'ID'):
                packet_info['duration'] = safe_str(dot11.ID)
            
            if hasattr(dot11, 'FCfield'):
                try:
                    fc = int(dot11.FCfield)
                    packet_info['flags_to_ds'] = 'Yes' if fc & 0x01 else 'No'
                    packet_info['flags_from_ds'] = 'Yes' if fc & 0x02 else 'No'
                    packet_info['flags_more_frag'] = 'Yes' if fc & 0x04 else 'No'
                    packet_info['flags_retry'] = 'Yes' if fc & 0x08 else 'No'
                    packet_info['flags_power_mgmt'] = 'Yes' if fc & 0x10 else 'No'
                    packet_info['flags_more_data'] = 'Yes' if fc & 0x20 else 'No'
                    packet_info['flags_protected'] = 'Yes' if fc & 0x40 else 'No'
                    packet_info['flags_order'] = 'Yes' if fc & 0x80 else 'No'
                except: 
                    pass
            
            packet_info['protocol'] = f"Dot11-{packet_info['wifi_type_subtype_name']}"
        
        # QoS Data
        if packet.haslayer(Dot11QoS):
            qos = packet[Dot11QoS]
            packet_info['qos_tid'] = safe_str(getattr(qos, 'TID', ''))
            packet_info['qos_eosp'] = safe_str(getattr(qos, 'EOSP', ''))
            packet_info['qos_ack_policy'] = safe_str(getattr(qos, 'Ack_Policy', ''))
        
        # Beacon Frame
        if packet.haslayer(Dot11Beacon):
            beacon = packet[Dot11Beacon]
            packet_info['beacon_interval'] = safe_str(getattr(beacon, 'beacon_interval', ''))
            if hasattr(beacon, 'cap'):
                try:
                    packet_info['capabilities'] = hex(int(beacon.cap))
                except:
                    packet_info['capabilities'] = safe_str(beacon.cap)
            
            if packet. haslayer(Dot11Elt):
                elt = packet[Dot11Elt]
                supported_rates_list = []
                crypto = set()
                vendor_info = []
                
                while isinstance(elt, Dot11Elt):
                    try:
                        elt_id = int(elt.ID) if hasattr(elt, 'ID') else 0
                        
                        if elt_id == 0:
                            try:
                                if elt.info:
                                    ssid = elt.info. decode('utf-8', errors='ignore')
                                    packet_info['ssid'] = ''.join(c if c.isprintable() else '' for c in ssid)
                                else:
                                    packet_info['ssid'] = '<Hidden>'
                            except:
                                packet_info['ssid'] = '<Error>'
                        
                        elif elt_id == 1:
                            if elt.info:
                                for byte in elt.info:
                                    rate = (byte & 0x7f) * 0.5
                                    supported_rates_list.append(f"{rate}")
                        
                        elif elt_id == 3:
                            if elt. info and len(elt.info) > 0:
                                packet_info['channel'] = str(elt.info[0])
                        
                        elif elt_id == 50:
                            if elt. info: 
                                for byte in elt.info:
                                    rate = (byte & 0x7f) * 0.5
                                    supported_rates_list.append(f"{rate}")
                        
                        elif elt_id == 48:
                            crypto.add('WPA2')
                            if len(elt.info) >= 2:
                                packet_info['rsn_version'] = str(int. from_bytes(elt.info[0:2], 'little'))
                            
                            try:
                                if len(elt.info) >= 6:
                                    cipher_types = {1: 'WEP-40', 2: 'TKIP', 4: 'CCMP', 5: 'WEP-104'}
                                    packet_info['group_cipher'] = cipher_types.get(elt.info[5], 'Unknown')
                            except:
                                pass
                        
                        elif elt_id == 221:
                            if elt. info and len(elt.info) >= 4:
                                if elt.info[0:3] == b'\x00\x50\xf2':
                                    if elt.info[3] == 1:
                                        crypto.add('WPA')
                                vendor_info.append(binascii.hexlify(elt.info[: 6]).decode())
                    
                    except:
                        pass
                    
                    elt = elt.payload if isinstance(elt. payload, Dot11Elt) else None
                
                if supported_rates_list:
                    packet_info['supported_rates'] = ', '.join(supported_rates_list[: 8])
                
                if crypto:
                    packet_info['encryption'] = ', '.join(sorted(crypto))
                else:
                    if packet.haslayer(Dot11Beacon):
                        try:
                            cap = int(packet[Dot11Beacon].cap) if hasattr(packet[Dot11Beacon], 'cap') else 0
                            if cap & 0x10:
                                packet_info['encryption'] = 'WEP'
                            else:
                                packet_info['encryption'] = 'Open'
                        except:
                            packet_info['encryption'] = 'Unknown'
                
                if vendor_info:
                    packet_info['vendor_specific'] = '; '.join(vendor_info[: 3])
            
            packet_info['info'] = f"Beacon:  SSID={packet_info['ssid']} CH={packet_info['channel']}"
        
        # Probe Request
        elif packet.haslayer(Dot11ProbeReq):
            if packet.haslayer(Dot11Elt):
                elt = packet[Dot11Elt]
                try:
                    if int(elt.ID) == 0:
                        if elt.info:
                            ssid = elt.info.decode('utf-8', errors='ignore')
                            packet_info['ssid'] = ''.join(c if c.isprintable() else '' for c in ssid)
                            packet_info['info'] = f"Probe Request: SSID={packet_info['ssid']}"
                        else:
                            packet_info['info'] = 'Probe Request:  (Broadcast)'
                except:
                    packet_info['info'] = 'Probe Request'
        
        # Probe Response
        elif packet.haslayer(Dot11ProbeResp):
            probe_resp = packet[Dot11ProbeResp]
            packet_info['beacon_interval'] = safe_str(getattr(probe_resp, 'beacon_interval', ''))
            
            if packet.haslayer(Dot11Elt):
                elt = packet[Dot11Elt]
                try:
                    if int(elt.ID) == 0 and elt.info:
                        ssid = elt.info.decode('utf-8', errors='ignore')
                        packet_info['ssid'] = ''.join(c if c.isprintable() else '' for c in ssid)
                        packet_info['info'] = f"Probe Response:  SSID={packet_info['ssid']}"
                except:
                    packet_info['info'] = 'Probe Response'
        
        # Association Request
        elif packet.haslayer(Dot11AssoReq):
            assoc_req = packet[Dot11AssoReq]
            packet_info['listen_interval'] = safe_str(getattr(assoc_req, 'listen_interval', ''))
            packet_info['capabilities'] = safe_str(getattr(assoc_req, 'cap', ''))
            
            if packet.haslayer(Dot11Elt):
                elt = packet[Dot11Elt]
                try:
                    if int(elt.ID) == 0 and elt.info:
                        ssid = elt.info.decode('utf-8', errors='ignore')
                        packet_info['ssid'] = ''. join(c if c.isprintable() else '' for c in ssid)
                except:
                    pass
            packet_info['info'] = f"Association Request: SSID={packet_info['ssid']}"
        
        # Association Response
        elif packet.haslayer(Dot11AssoResp):
            assoc_resp = packet[Dot11AssoResp]
            packet_info['status_code'] = safe_str(getattr(assoc_resp, 'status', ''))
            packet_info['capabilities'] = safe_str(getattr(assoc_resp, 'cap', ''))
            packet_info['info'] = f"Association Response: Status={packet_info['status_code']}"
        
        # Authentication
        elif packet.haslayer(Dot11Auth):
            auth = packet[Dot11Auth]
            packet_info['auth_algorithm'] = safe_str(getattr(auth, 'algo', ''))
            packet_info['auth_seq'] = safe_str(getattr(auth, 'seqnum', ''))
            packet_info['status_code'] = safe_str(getattr(auth, 'status', ''))
            packet_info['info'] = f"Authentication:  Alg={packet_info['auth_algorithm']} Seq={packet_info['auth_seq']}"
        
        # Deauthentication
        elif packet.haslayer(Dot11Deauth):
            deauth = packet[Dot11Deauth]
            packet_info['reason_code'] = safe_str(getattr(deauth, 'reason', ''))
            packet_info['info'] = f"Deauthentication: Reason={packet_info['reason_code']}"
        
        # Disassociation
        elif packet.haslayer(Dot11Disas):
            disas = packet[Dot11Disas]
            packet_info['reason_code'] = safe_str(getattr(disas, 'reason', ''))
            packet_info['info'] = f"Disassociation: Reason={packet_info['reason_code']}"
        
        # EAPOL
        if packet.haslayer(EAPOL):
            packet_info['protocol'] = 'EAPOL'
            packet_info['info'] = 'EAPOL (WPA Handshake)'
        
        # Encryption
        if packet.haslayer(Dot11CCMP):
            packet_info['ccmp_pn'] = 'Yes'
        if packet.haslayer(Dot11TKIP):
            packet_info['tkip_tsc'] = 'Yes'
        
        # Ethernet
        if packet.haslayer(Ether):
            ether = packet[Ether]
            if not packet_info['src_mac']:
                packet_info['src_mac'] = safe_str(ether.src)
            if not packet_info['dst_mac']: 
                packet_info['dst_mac'] = safe_str(ether.dst)
            if not packet_info['protocol']: 
                packet_info['protocol'] = 'Ethernet'
        
        # ARP
        if packet.haslayer(ARP):
            arp = packet[ARP]
            packet_info['protocol'] = 'ARP'
            packet_info['src_ip'] = safe_str(arp.psrc)
            packet_info['dst_ip'] = safe_str(arp.pdst)
            if not packet_info['src_mac']: 
                packet_info['src_mac'] = safe_str(arp.hwsrc)
            if not packet_info['dst_mac']: 
                packet_info['dst_mac'] = safe_str(arp.hwdst)
            op = int(arp.op) if hasattr(arp, 'op') else 0
            packet_info['info'] = f"ARP {'Request' if op == 1 else 'Reply' if op == 2 else str(op)}"
        
        # IP
        if packet.haslayer(IP):
            ip = packet[IP]
            packet_info['src_ip'] = safe_str(ip.src)
            packet_info['dst_ip'] = safe_str(ip.dst)
            packet_info['ip_version'] = safe_str(ip.version)
            packet_info['ttl'] = safe_str(ip.ttl)
            packet_info['ip_tos'] = safe_str(ip.tos)
            packet_info['ip_id'] = safe_str(ip. id)
            packet_info['ip_flags'] = safe_str(ip. flags)
            packet_info['ip_frag_offset'] = safe_str(ip.frag)
            packet_info['checksum'] = safe_str(ip.chksum)
            
            proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            packet_info['protocol'] = proto_map.get(int(ip.proto), f'IP-{ip.proto}')
        
        # IPv6
        if packet.haslayer(IPv6):
            ipv6 = packet[IPv6]
            packet_info['src_ip'] = safe_str(ipv6.src)
            packet_info['dst_ip'] = safe_str(ipv6.dst)
            packet_info['ip_version'] = '6'
            packet_info['ttl'] = safe_str(ipv6.hlim)
            packet_info['protocol'] = 'IPv6'
        
        # TCP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            packet_info['src_port'] = safe_str(tcp. sport)
            packet_info['dst_port'] = safe_str(tcp.dport)
            packet_info['protocol'] = 'TCP'
            
            if hasattr(tcp, 'flags'):
                try:
                    flags_val = int(tcp.flags)
                    flag_names = []
                    if flags_val & 0x01:  flag_names.append('F')
                    if flags_val & 0x02: flag_names.append('S')
                    if flags_val & 0x04: flag_names.append('R')
                    if flags_val & 0x08: flag_names.append('P')
                    if flags_val & 0x10: flag_names.append('A')
                    if flags_val & 0x20: flag_names.append('U')
                    if flags_val & 0x40: flag_names.append('E')
                    if flags_val & 0x80: flag_names.append('C')
                    packet_info['tcp_flags'] = ''.join(flag_names) if flag_names else str(flags_val)
                except:
                    packet_info['tcp_flags'] = safe_str(tcp.flags)
            
            packet_info['tcp_seq'] = safe_str(tcp. seq)
            packet_info['tcp_ack'] = safe_str(tcp.ack)
            packet_info['tcp_window'] = safe_str(tcp. window)
            packet_info['checksum'] = safe_str(tcp.chksum)
            
            if hasattr(tcp, 'payload') and tcp.payload:
                payload_bytes = bytes(tcp.payload)
                packet_info['payload_size'] = str(len(payload_bytes))
                if len(payload_bytes) > 0:
                    packet_info['payload_hex'] = binascii.hexlify(payload_bytes[: 32]).decode()
            
            if not packet_info['info']:
                packet_info['info'] = f"TCP {tcp.sport}->{tcp.dport} [{packet_info['tcp_flags']}]"
            
            port_protocols = {
                80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
                23: 'Telnet', 25: 'SMTP', 110: 'POP3', 143: 'IMAP', 3389: 'RDP'
            }
            sport = int(tcp.sport)
            dport = int(tcp.dport)
            for port, proto in port_protocols. items():
                if sport == port or dport == port:
                    packet_info['protocol'] = proto
                    break
        
        # UDP
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            packet_info['src_port'] = safe_str(udp.sport)
            packet_info['dst_port'] = safe_str(udp. dport)
            packet_info['protocol'] = 'UDP'
            packet_info['udp_length'] = safe_str(udp.len)
            packet_info['checksum'] = safe_str(udp.chksum)
            
            if hasattr(udp, 'payload') and udp.payload:
                payload_bytes = bytes(udp.payload)
                packet_info['payload_size'] = str(len(payload_bytes))
                if len(payload_bytes) > 0:
                    packet_info['payload_hex'] = binascii. hexlify(payload_bytes[: 32]).decode()
            
            if not packet_info['info']: 
                packet_info['info'] = f"UDP {udp.sport}->{udp.dport}"
            
            sport = int(udp.sport)
            dport = int(udp.dport)
            if sport == 53 or dport == 53:
                packet_info['protocol'] = 'DNS'
            elif sport in [67, 68] or dport in [67, 68]:
                packet_info['protocol'] = 'DHCP'
            elif sport == 123 or dport == 123:
                packet_info['protocol'] = 'NTP'
        
        # ICMP
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            packet_info['protocol'] = 'ICMP'
            packet_info['checksum'] = safe_str(icmp.chksum)
            
            icmp_types = {0: 'Echo Reply', 3: 'Dest Unreachable', 8: 'Echo Request', 11: 'Time Exceeded'}
            icmp_type = int(icmp.type) if hasattr(icmp, 'type') else 0
            if not packet_info['info']:
                packet_info['info'] = f"ICMP {icmp_types.get(icmp_type, f'Type {icmp_type}')}"
        
        # DNS
        if packet.haslayer(DNS):
            dns = packet[DNS]
            qr = int(dns.qr) if hasattr(dns, 'qr') else 0
            if qr == 0 and dns.qd: 
                qname = dns.qd.qname. decode() if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
                qname = ''.join(c if c.isprintable() else '' for c in qname)
                packet_info['info'] = f"DNS Query: {qname}"
            elif qr == 1:
                packet_info['info'] = f"DNS Response: {int(dns.ancount) if hasattr(dns, 'ancount') else 0} answer(s)"
        
        # Raw payload
        if packet.haslayer(Raw) and not packet_info['payload_hex']:
            raw = packet[Raw]
            raw_bytes = bytes(raw.load)
            packet_info['payload_size'] = str(len(raw_bytes))
            if len(raw_bytes) > 0:
                packet_info['payload_hex'] = binascii.hexlify(raw_bytes[: 32]).decode()
        
        # Summary fallback
        if not packet_info['info']:
            try:
                summary = packet.summary()
                packet_info['summary'] = ''.join(c if c.isprintable() else ' ' for c in summary)
                packet_info['info'] = packet_info['summary'] if packet_info['summary'] else f"{packet_info['protocol']} packet"
            except:
                packet_info['info'] = f"{packet_info['protocol']} packet"
    
    except Exception as e:
        packet_info['info'] = f"Error: {str(e)[:100]}"
        packet_info['protocol'] = 'ERROR'
    
    # Final safe string conversion
    for key in packet_info:
        packet_info[key] = safe_str(packet_info[key])
    
    return packet_info

def pcap_to_csv(pcap_file):
    """Convert PCAP to CSV"""
    try:
        packets = rdpcap(pcap_file)
        
        packet_data = []
        for packet in packets:
            packet_data.append(extract_packet_info(packet))
        
        df = pd.DataFrame(packet_data)
        
        for col in df.columns:
            df[col] = df[col]. astype(str)
        
        df = df.replace('nan', '')
        df = df.replace('None', '')
        
        return df, None
    
    except Exception as e:
        return None, str(e)

def main():
    st.set_page_config(
        page_title="PCAP to CSV - Ultimate Extractor",
        page_icon="📊",
        layout="wide"
    )
    
    st.title("📊 PCAP to CSV Converter - Ultimate Packet Extractor")
    st.markdown("Extract **60+ fields** from PCAP files (WiFi 802.11, Ethernet, IP, TCP, UDP)")
    
    with st.sidebar:
        st.header("📡 About")
        st.info(
            "**Ultimate PCAP Extractor**\n\n"
            "Extracts 60+ fields including:\n\n"
            "**WiFi 802.11:**\n"
            "- MAC addresses & BSSID\n"
            "- SSID, Channel, Encryption\n"
            "- Signal strength, Data rate\n"
            "- Frame types & flags\n"
            "- Beacon/Probe/Auth frames\n\n"
            "**Network:**\n"
            "- IP addresses & ports\n"
            "- TCP/UDP details\n"
            "- Payload data\n"
            "- Protocol detection"
        )
        
        st.header("⚙️ Settings")
        show_empty_cols = st.checkbox("Show empty columns", value=False)
    
    uploaded_file = st.file_uploader(
        "Choose a PCAP file",
        type=['pcap', 'pcapng', 'cap'],
        help="Upload any PCAP file"
    )
    
    if uploaded_file is not None:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("📁 File", uploaded_file.name)
        with col2:
            st.metric("💾 Size", f"{uploaded_file.size / 1024:.2f} KB")
        with col3:
            st.metric("📝 Type", "PCAP")
        
        if st.button("🔄 Extract All Data", type="primary"):
            with st.spinner("Extracting data..."):
                temp_file = f"temp_{uploaded_file.name}"
                with open(temp_file, "wb") as f:
                    f.write(uploaded_file. getvalue())
                
                df, error = pcap_to_csv(temp_file)
                
                import os
                os.remove(temp_file)
                
                if error:
                    st.error(f"❌ Error: {error}")
                else:
                    st. success(f"✅ Extracted {len(df)} packets with {len(df.columns)} fields!")
                    st.session_state['df'] = df
                    st. session_state['uploaded_filename'] = uploaded_file.name
    
    if 'df' in st.session_state:
        df = st.session_state['df']
        
        if not show_empty_cols:
            df_display = df.loc[:, (df != '').any(axis=0)]
        else:
            df_display = df
        
        st.divider()
        
        st.subheader("📈 Statistics")
        col1, col2, col3, col4, col5 = st.columns(5)
        with col1:
            st.metric("📦 Packets", len(df))
        with col2:
            st. metric("📊 Total Fields", len(df.columns))
        with col3:
            st.metric("✅ Non-Empty", len(df_display.columns))
        with col4:
            st.metric("🔢 Protocols", df['protocol'].nunique())
        with col5:
            total = df['length'].apply(lambda x: int(x) if x.isdigit() else 0).sum()
            st.metric("💽 Data", f"{total/1024:.1f} KB")
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("📊 Protocols")
            protocol_counts = df['protocol'].value_counts().head(10)
            st.bar_chart(protocol_counts)
        
        with col2:
            st.subheader("🔝 Top 10")
            st.dataframe(protocol_counts.reset_index().rename(columns={'index': 'Protocol', 'protocol': 'Count'}), use_container_width=True, hide_index=True)
        
        if 'ssid' in df.columns and (df['ssid'] != '').any():
            st.subheader("📡 WiFi Networks")
            wifi_cols = ['ssid', 'bssid', 'channel', 'encryption', 'signal_strength']
            available_cols = [c for c in wifi_cols if c in df.columns]
            wifi_df = df[df['ssid'] != ''][available_cols]. drop_duplicates(subset=['ssid', 'bssid'] if 'bssid' in available_cols else ['ssid'])
            st.dataframe(wifi_df, use_container_width=True)
        
        st.subheader("👁️ Data Preview")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            protocols = ['All'] + sorted([p for p in df['protocol'].unique() if p])
            selected_protocol = st.selectbox("Protocol", protocols)
        with col2:
            num_rows = st.slider("Rows", 10, 100, 25)
        with col3:
            search_term = st.text_input("🔍 Search", "")
        
        filtered_df = df_display. copy()
        if selected_protocol != 'All': 
            filtered_df = filtered_df[filtered_df['protocol'] == selected_protocol]
        if search_term:
            mask = filtered_df. apply(lambda row: row. astype(str).str.contains(search_term, case=False).any(), axis=1)
            filtered_df = filtered_df[mask]
        
        st. dataframe(filtered_df.head(num_rows), use_container_width=True, height=400)
        
        with st.expander("📋 Field Statistics"):
            col_info = pd.DataFrame({
                'Field':  df.columns,
                'Non-Empty': [(df[col] != '').sum() for col in df.columns],
                'Fill %': [f"{((df[col] != '').sum() / len(df) * 100):.1f}%" for col in df.columns]
            })
            st.dataframe(col_info, use_container_width=True, height=400)
        
        st.subheader("💾 Download")
        
        col1, col2 = st.columns(2)
        
        with col1:
            try:
                csv_all = df.to_csv(index=False, encoding='utf-8-sig', quoting=1, escapechar='\\')
                st.download_button(
                    label="📥 Full CSV (All Fields)",
                    data=csv_all,
                    file_name=f"full_{st.session_state. get('uploaded_filename', 'pcap')}.csv",
                    mime="text/csv",
                    type="primary"
                )
                st.caption(f"✅ {len(df. columns)} fields")
            except Exception as e: 
                st.error(f"Error:  {e}")
        
        with col2:
            try:
                df_non_empty = df. loc[:, (df != '').any(axis=0)]
                csv_filtered = df_non_empty.to_csv(index=False, encoding='utf-8-sig', quoting=1, escapechar='\\')
                st.download_button(
                    label="📥 Filtered CSV",
                    data=csv_filtered,
                    file_name=f"filtered_{st.session_state.get('uploaded_filename', 'pcap')}.csv",
                    mime="text/csv"
                )
                st.caption(f"✅ {len(df_non_empty.columns)} fields")
            except Exception as e:
                st.error(f"Error: {e}")
        
        st.info(f"📊 Showing {len(filtered_df)} of {len(df)} packets")

if __name__ == "__main__":
    main()