import socket
import folium
import requests
import ipaddress
import pingparsing

# Função para realizar o TraceRoute e Ping ao mesmo tempo


def traceroute_with_ping(host, max_hops=30, timeout=2, ping_count=4):
    print(f"TraceRoute para {host}:")

    hops = []
    dest_addr = socket.gethostbyname(host)
    port = 33434  
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')
    ping_parser = pingparsing.PingParsing()
    transmitter = pingparsing.PingTransmitter()

    for ttl in range(1, max_hops + 1):
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        recv_socket.settimeout(timeout)

        recv_socket.bind(("", port))
        send_socket.sendto(b"", (host, port))

        curr_addr = None
        try:
            _, curr_addr = recv_socket.recvfrom(512)
            curr_addr = curr_addr[0]
            hops.append(curr_addr)

            # Fazer ping no hop atual
            transmitter.destination = curr_addr
            transmitter.count = ping_count
            ping_result = transmitter.ping()

            if ping_result.returncode == 0:
                ping_stats = ping_parser.parse(ping_result.stdout)

                packet_loss = ping_stats.packet_loss_rate
                packets_sent = ping_stats.packet_transmit
                min_time = ping_stats.rtt_min
                avg_time = ping_stats.rtt_avg
                max_time = ping_stats.rtt_max
                mdev_time = ping_stats.rtt_mdev

                print(
                    f"{ttl}: {curr_addr} | Sent: {packets_sent} | Loss: {packet_loss} % | Last: {avg_time}ms | Best: {min_time}ms | Worst: {max_time}ms | Std.Dev: {mdev_time}")
            else:
                print(f"{ttl}: {curr_addr} | Erro no ping")

        except socket.timeout:
            print(f"{ttl}: * (timeout)")
        except socket.error as e:
            print(f"{ttl}: erro no socket - {e}")
        finally:
            send_socket.close()
            recv_socket.close()

        if curr_addr == dest_addr:
            print("Destino alcançado!")
            break
    return hops

def is_private_ip(ip):
    return ipaddress.ip_address(ip).is_private

def get_coordinates(ip):
    if is_private_ip(ip):
        print(f"IP {ip} é privado. Sem coordenadas públicas conhecidas.")
        return None

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                lat, lon = data['lat'], data['lon']
                # Exibe as coordenadas no console
                print(f"Coordenadas de {ip}: ({lat}, {lon})")
                return lat, lon
            else:
                print(f"API retornou falha para o IP {ip}: {data['message']}")
                return None
        else:
            print(
                f"Erro ao conectar-se à API para o IP {ip}. Status HTTP: {response.status_code}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Erro de conexão ao tentar obter localização de {ip}: {e}")
        return None

def main():
    destino = input("Digite o IP ou endereço do host: ")
    try:
        hops= traceroute_with_ping(destino)
        #if hops:
            # aqui tua função de plotagem lazaro, as coordenadas estão na lista hops, por isso joguei ali como parametro.
            #plotar_mapa(hops)
        #else:
           # print("Não foi possível rastrear a rota.")
    except socket.gaierror:
        print(
            f"Erro: Host '{destino}' não encontrado. Verifique o endereço e tente novamente.")
    except Exception as e:
        print(f"Erro inesperado: {e}")


if __name__ == "__main__":
    main()