#!/usr/bin/env python3

import argparse
import ipaddress
import socket
import struct
import time
import sys
import threading
import fcntl
import os

# Constantes para ioctl
SIOCGIFHWADDR = 0x8927
SIOCGIFINDEX = 0x8933

# Função para obter o endereço MAC da interface de rede
def get_mac_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, struct.pack('256s', bytes(ifname[:15], 'utf-8')))
    mac = ':'.join('%02x' % b for b in info[18:24])
    return mac

# Função para obter o índice da interface de rede
def get_ifindex(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, struct.pack('256s', bytes(ifname[:15], 'utf-8')))
    ifindex = struct.unpack('I', ifreq[16:20])[0]
    return ifindex

# Função para converter endereço MAC de string para bytes
def mac_str_to_bytes(mac_str):
    return bytes(int(b, 16) for b in mac_str.split(':'))

# Função para calcular o checksum do pacote IP
def checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    res = sum(struct.unpack("!%sH" % (len(data) // 2), data))
    while res > 0xffff:
        res = (res & 0xffff) + (res >> 16)
    return ~res & 0xffff

# Função para criar o pacote ICMP dentro de um quadro Ethernet
def create_frame(src_mac, dst_mac, src_ip, dst_ip, iface_index):
    # Cabeçalho Ethernet
    eth_header = struct.pack('!6s6sH',
                             dst_mac,
                             src_mac,
                             0x0800)  # EtherType para IPv4

    # Cabeçalho IP
    version_ihl = (4 << 4) + 5
    tos = 0
    total_length = 20 + 8  # IP header + ICMP header
    identification = 54321
    flags_fragment_offset = 0
    ttl = 64
    protocol = socket.IPPROTO_ICMP
    header_checksum = 0
    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)

    ip_header = struct.pack('!BBHHHBBH4s4s',
                            version_ihl,
                            tos,
                            total_length,
                            identification,
                            flags_fragment_offset,
                            ttl,
                            protocol,
                            header_checksum,
                            src_ip_bytes,
                            dst_ip_bytes)

    # Calcula o checksum do cabeçalho IP
    ip_checksum = checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            version_ihl,
                            tos,
                            total_length,
                            identification,
                            flags_fragment_offset,
                            ttl,
                            protocol,
                            ip_checksum,
                            src_ip_bytes,
                            dst_ip_bytes)

    # Cabeçalho ICMP
    icmp_type = 8  # Echo request
    code = 0
    icmp_checksum = 0
    identifier = os.getpid() & 0xFFFF
    sequence_number = 1
    icmp_header = struct.pack('!BBHHH',
                              icmp_type,
                              code,
                              icmp_checksum,
                              identifier,
                              sequence_number)

    # Dados ICMP
    data = struct.pack('d', time.time())

    # Calcula o checksum do ICMP
    icmp_checksum = checksum(icmp_header + data)
    icmp_header = struct.pack('!BBHHH',
                              icmp_type,
                              code,
                              icmp_checksum,
                              identifier,
                              sequence_number)

    # Monta o pacote completo
    packet = eth_header + ip_header + icmp_header + data
    return packet

# Função para enviar o quadro Ethernet e receber a resposta
def ping(ifname, src_mac_str, src_ip, dst_ip, timeout):
    try:
        # Converte endereços MAC para bytes
        src_mac = mac_str_to_bytes(src_mac_str)
        dst_mac = b'\xff\xff\xff\xff\xff\xff'  # Broadcast MAC

        # Cria um socket raw com AF_PACKET
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        s.bind((ifname, 0))

        # Obter índice da interface
        ifindex = get_ifindex(ifname)

        # Cria o quadro Ethernet com o pacote ICMP
        frame = create_frame(src_mac, dst_mac, src_ip, dst_ip, ifindex)

        start_time = time.time()
        s.send(frame)

        # Configura o socket para não bloquear
        s.settimeout(timeout)

        while True:
            try:
                raw_data, addr = s.recvfrom(65535)
                time_received = time.time()
                # Verifica se é uma resposta ICMP Echo Reply
                eth_length = 14
                eth_header = raw_data[:eth_length]
                eth = struct.unpack('!6s6sH', eth_header)
                if eth[2] != 0x0800:  # EtherType IPv4
                    continue

                ip_header = raw_data[eth_length:eth_length+20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                protocol = iph[6]
                if protocol != socket.IPPROTO_ICMP:
                    continue

                icmp_offset = eth_length + (iph[0] & 0xF) * 4
                icmp_header = raw_data[icmp_offset:icmp_offset+8]
                icmph = struct.unpack('!BBHHH', icmp_header)
                icmp_type = icmph[0]
                if icmp_type == 0:  # Echo Reply
                    return time_received - start_time
            except socket.timeout:
                return None
    except PermissionError:
        print("Permissão negada: você precisa de privilégios de administrador para executar este script.")
        sys.exit()
    except Exception as e:
        print(f"Erro: {e}")
        sys.exit()

# Função principal
def main():
    # Processa os argumentos de linha de comando
    parser = argparse.ArgumentParser(description='Varredura de rede usando ICMP Echo Requests com AF_PACKET.')
    parser.add_argument('rede', type=str, help='Rede e máscara (ex: 192.168.1.128/25)')
    parser.add_argument('timeout', type=int, help='Tempo limite em milissegundos')
    parser.add_argument('interface', type=str, help='Interface de rede (ex: eth0)')
    args = parser.parse_args()

    # Converte o tempo limite para segundos
    timeout = args.timeout / 1000.0  # Convertendo milissegundos para segundos

    # Gera a lista de IPs na rede, excluindo rede e broadcast
    try:
        rede = ipaddress.ip_network(args.rede, strict=False)
    except ValueError as e:
        print(f"Erro ao interpretar a rede: {e}")
        return

    ips = [str(ip) for ip in rede.hosts()]
    total_maquinas = len(ips)

    # Obtém o endereço IP e MAC da interface
    src_ip = socket.gethostbyname(socket.gethostname())
    src_mac = get_mac_address(args.interface)

    print(f"Endereço MAC da interface {args.interface}: {src_mac}")
    print(f"Endereço IP da interface {args.interface}: {src_ip}")

    # Inicia a varredura
    hosts_ativos = []
    tempo_inicio_varredura = time.time()

    print(f"Iniciando varredura na rede {args.rede}...")

    for ip in ips:
        tempo_inicio = time.time()
        delay = ping(args.interface, src_mac, src_ip, ip, timeout)
        tempo_fim = time.time()

        if delay is not None:
            # Calcula o tempo de resposta em milissegundos
            tempo_resposta = delay * 1000
            hosts_ativos.append((ip, tempo_resposta))
            print(f"Host ativo: {ip} - Tempo de resposta: {tempo_resposta:.2f} ms")
        else:
            print(f"Host inativo: {ip}")

    tempo_fim_varredura = time.time()
    tempo_total_varredura = tempo_fim_varredura - tempo_inicio_varredura

    # Exibe os resultados
    print("\n--- Resultados da Varredura ---")
    print(f"Número de máquinas ativas: {len(hosts_ativos)}")
    print(f"Número total de máquinas na rede: {total_maquinas}")
    print(f"Tempo total de varredura: {tempo_total_varredura:.2f} segundos")

    print("\nHosts ativos e seus tempos de resposta:")
    for ip, tempo_resposta in hosts_ativos:
        print(f"{ip} - {tempo_resposta:.2f} ms")

if __name__ == "__main__":
    main()
