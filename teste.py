import socket
import os
import folium
import platform
import requests
import ipaddress


# Função para realizar o TraceRoute usando socket
def traceroute(host, max_hops=30, timeout=2):
    print(f"TraceRoute para {host}:")
    hops = []
    dest_addr = socket.gethostbyname(host)
    port = 33434  # Porta arbitrária
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')

    for ttl in range(1, max_hops + 1):
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        recv_socket.settimeout(timeout)

        recv_socket.bind(("", port))
        send_socket.sendto(b"", (host, port))

        curr_addr = None
        try:
            data, curr_addr = recv_socket.recvfrom(512)
            curr_addr = curr_addr[0]
            hops.append(curr_addr)
            print(f"{ttl}: {curr_addr}")
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


def ping(host):
    print(f"\nPing para {host}:")
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    response = os.system(f"ping {param} 4 {host}")

    if response == 0:
        print(f"{host} está respondendo ao ping.")
    else:
        print(f"{host} não está respondendo ao ping.")


def is_private_ip(ip):
    return ipaddress.ip_address(ip).is_private


def get_coordinates(ip, last_public_coords=None):
    if is_private_ip(ip):
        if last_public_coords:
            print(
                f"IP {ip} é privado. Usando coordenadas aproximadas do último hop público.")
            return last_public_coords
        else:
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
        hops = traceroute(destino)
        ping(destino)
        if hops:
            # aqui tua função de plotagem lazaro, as coordenadas estão na lista hops, por isso joguei ali como parametro.
            plotar_mapa(hops)
        else:
            print("Não foi possível rastrear a rota.")
    except socket.gaierror:
        print(
            f"Erro: Host '{destino}' não encontrado. Verifique o endereço e tente novamente.")
    except Exception as e:
        print(f"Erro inesperado: {e}")


if __name__ == "__main__":
    main()
