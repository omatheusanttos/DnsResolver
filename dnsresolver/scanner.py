import dns.resolver
import concurrent.futures
import time
import argparse
import requests
import requests.exceptions
from tqdm import tqdm
import socket
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import subprocess
import shutil

title = """
$$$$$$$\                      $$$$$$$\                                $$\                                
$$  __$$\                     $$  __$$\                               $$ |                               
$$ |  $$ |$$$$$$$\   $$$$$$$\ $$ |  $$ | $$$$$$\   $$$$$$$\  $$$$$$\  $$ |$$\    $$\  $$$$$$\   $$$$$$\  
$$ |  $$ |$$  __$$\ $$  _____|$$$$$$$  |$$  __$$\ $$  _____|$$  __$$\ $$ |\$$\  $$  |$$  __$$\ $$  __$$\ 
$$ |  $$ |$$ |  $$ |\$$$$$$\  $$  __$$< $$$$$$$$ |\$$$$$$\  $$ /  $$ |$$ | \$$\$$  / $$$$$$$$ |$$ |  \__|
$$ |  $$ |$$ |  $$ | \____$$\ $$ |  $$ |$$   ____| \____$$\ $$ |  $$ |$$ |  \$$$  /  $$   ____|$$ |      
$$$$$$$  |$$ |  $$ |$$$$$$$  |$$ |  $$ |\$$$$$$$\ $$$$$$$  |\$$$$$$  |$$ |   \$  /   \$$$$$$$\ $$ |      
\_______/ \__|  \__|\_______/ \__|  \__| \_______|\_______/  \______/ \__|    \_/     \_______|\__|

"""

# --- Configurações ajustáveis ---
DEFAULT_DNS_TIMEOUT = 1.0   # seconds por tentativa de DNS (reduzido)
DEFAULT_DNS_LIFETIME = 2.0  # tempo total permitido por query (reduzido)
DEFAULT_MAX_WORKERS = 50
DEFAULT_HTTP_WORKERS = 20
HTTP_TIMEOUT = 10

def have_bin(name): # (manter) Função que fiz para verificar se o usuário tem os binários das ferramentas externas que vão ser usadas. 
    import shutil
    return shutil.which(name) is not None

def run_subfinder(domain, timeout=120):

    if not have_bin("subfinder"):
        print("[subfinder] não encontrado no PATH. Skipping.")
        return []
    
    cmd = ["subfinder", "-d", domain, "-silent"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        stdout = proc.stdout or ""
        lines = [l.strip() for l in stdout.splitlines() if l.strip()]
        return lines
    except subprocess.TimeoutExpired:
        print("[subfinder] timeout expirado.")
        return []
    except Exception as e:
        print("[subfinder] erro:", e)
        return []
    
    print(lines)
run_subfinder("inbursa.com.br")


def buscar_subdominio(subdominio_completo, resolver_obj=None, tipos_registro=None, dns_cache=None):
    if dns_cache is None:
        dns_cache = {}
    if subdominio_completo in dns_cache:
        return dns_cache[subdominio_completo]
    if resolver_obj is None:
        resolver_obj = dns.resolver.Resolver()
        resolver_obj.timeout = DEFAULT_DNS_TIMEOUT
        resolver_obj.lifetime = DEFAULT_DNS_LIFETIME
        # Força nameservers confiáveis por padrão (evita DNS local lento)
        resolver_obj.nameservers = ['1.1.1.1', '8.8.8.8']
    if tipos_registro is None:
        tipos_registro = ['A', 'AAAA', 'MX', 'NS']

    ordem = ['A', 'AAAA'] + [t for t in tipos_registro if t not in ('A', 'AAAA')]

    for tipo in ordem:
        try:
            # Passa lifetime explicitamente para evitar esperas longas
            answers = resolver_obj.resolve(subdominio_completo, tipo, lifetime=DEFAULT_DNS_LIFETIME)
            for rdata in answers:
                valor = rdata.to_text()
                resultado = (subdominio_completo, valor, tipo)
                dns_cache[subdominio_completo] = resultado
                return resultado
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            # sem resposta para esse tipo — tenta o próximo
            pass
        except dns.exception.Timeout:
            # timeout: rejeita rápido e tenta o próximo tipo
            pass
        except Exception:
            # erros inesperados não param tudo
            pass

    dns_cache[subdominio_completo] = (None, None, None)
    return None, None, None

def is_wildcard(dominio, ip_wildcard, resolver_obj=None):
    try:
        if resolver_obj is None:
            resolver_obj = dns.resolver.Resolver()
            resolver_obj.timeout = DEFAULT_DNS_TIMEOUT
            resolver_obj.lifetime = DEFAULT_DNS_LIFETIME
            resolver_obj.nameservers = ['1.1.1.1', '8.8.8.8']

        answers = resolver_obj.resolve(f"naoexiste.{dominio}", "A", lifetime=DEFAULT_DNS_LIFETIME)
        if answers and answers[0].to_text() == ip_wildcard:
            return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return False
    except dns.exception.Timeout:
        return False
    except Exception:
        return False
    return False

def verificar_http(endereco_dns, ip_from_dns=None, session=None, timeout_http=HTTP_TIMEOUT):
    resultados = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    if session is None:
        session = requests.Session()

    def _obter_ip(host):
        if ip_from_dns:
            return ip_from_dns
        try:
            ai = socket.getaddrinfo(host, None)
            if ai and len(ai) > 0:
                return ai[0][4][0]
        except Exception:
            return ""
        return ""

    try:
        url_https = f"https://{endereco_dns}"
        resposta = session.get(url_https, timeout=timeout_http, allow_redirects=True, headers=headers)
        ip = _obter_ip(endereco_dns)
        resultados.append((resposta.url, resposta.status_code, "HTTPS", ip))
    except requests.exceptions.Timeout:
        resultados.append((f"https://{endereco_dns}", "Tempo limite excedido", "HTTPS", ""))
    except requests.exceptions.ConnectionError:
        resultados.append((f"https://{endereco_dns}", "Conexão falhou", "HTTPS", ""))
    except requests.exceptions.RequestException as e:
        resultados.append((f"https://{endereco_dns}", f"Erro: {str(e)}", "HTTPS", ""))

    try:
        url_http = f"http://{endereco_dns}"
        resposta = session.get(url_http, timeout=timeout_http, allow_redirects=True, headers=headers)
        ip = _obter_ip(endereco_dns)
        resultados.append((resposta.url, resposta.status_code, "HTTP", ip))
    except requests.exceptions.Timeout:
        resultados.append((f"http://{endereco_dns}", "Tempo limite excedido", "HTTP", ""))
    except requests.exceptions.ConnectionError:
        resultados.append((f"http://{endereco_dns}", "Conexão falhou", "HTTP", ""))
    except requests.exceptions.RequestException as e:
        resultados.append((f"http://{endereco_dns}", f"Erro: {str(e)}", "HTTP", ""))

    return resultados

def main():
    print(title)
    parser = argparse.ArgumentParser(description='Escaneador de Subdomínio (ajustado para latência inicial)')
    parser.add_argument('-d', '--dominio', required=True, help='O domínio que será escaneado.')
    parser.add_argument('-w', '--wordlist', required=True, help='O caminho para a wordlist.')
    parser.add_argument('--dns-workers', type=int, default=DEFAULT_MAX_WORKERS, help='Número de threads para probes DNS.')
    parser.add_argument('--http-workers', type=int, default=DEFAULT_HTTP_WORKERS, help='Número de threads para checagem HTTP.')
    parser.add_argument('--dns-timeout', type=float, default=DEFAULT_DNS_TIMEOUT, help='Timeout por tentativa DNS (s).')
    parser.add_argument('--dns-lifetime', type=float, default=DEFAULT_DNS_LIFETIME, help='Lifetime total por query DNS (s).')
    args = parser.parse_args()
    dominio = args.dominio
    wordlist_caminho = args.wordlist

    tipo_traducao = {
        'A': 'IPv4',
        'AAAA': 'IPv6',
        'MX': 'Servidor de Email',
        'NS': 'Servidor de Nomes'
    }

    subdominios_a_testar = []
    try:
        with open(wordlist_caminho, 'r', encoding='utf-8', errors='ignore') as arquivo:
            for linha in arquivo:
                w = linha.strip()
                if w:
                    subdominios_a_testar.append(w)
    except FileNotFoundError:
        print(f"Erro: O arquivo '{wordlist_caminho}' não foi encontrado.")
        return

    subdominios_encontrados = []

    print("Iniciando a busca de DNS...")
    start_time = time.time()

    resolver_obj = dns.resolver.Resolver()
    resolver_obj.timeout = args.dns_timeout
    resolver_obj.lifetime = args.dns_lifetime
    # FORÇA nameservers públicos confiáveis para reduzir latência inicial causada por DNS local ruim
    resolver_obj.nameservers = ['1.1.1.1', '8.8.8.8']

    ip_wildcard = None
    try:
        wildcard_test_name = f"naoexiste-{int(time.time()*1000)}.{dominio}"
        wildcard_resolvido = resolver_obj.resolve(wildcard_test_name, "A", lifetime=args.dns_lifetime)
        if wildcard_resolvido:
            ip_wildcard = wildcard_resolvido[0].to_text()
            print(f"IP Wildcard detectado: {ip_wildcard}")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        print("Nenhum IP Wildcard detectado.")
    except Exception:
        print("Erro ao testar wildcard — prosseguindo sem wildcard.")

    dns_cache = {}

    dns_workers = min(max(4, args.dns_workers), len(subdominios_a_testar) or 1)
    http_workers = min(max(2, args.http_workers), len(subdominios_a_testar) or 1)

    nomes = [f"{word}.{dominio}" for word in subdominios_a_testar]

    with concurrent.futures.ThreadPoolExecutor(max_workers=dns_workers) as executor:
        futures = {
            executor.submit(buscar_subdominio, nome, resolver_obj, ['A', 'AAAA', 'MX', 'NS'], dns_cache): nome
            for nome in nomes
        }

        for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="DNS", unit="req"):
            try:
                subdom_completo, registro, tipo = future.result()
                if subdom_completo:
                    if ip_wildcard and registro == ip_wildcard:
                        continue
                    subdominios_encontrados.append((subdom_completo, registro, tipo))
            except Exception:
                pass

    end_time = time.time()

    print("\n-------------------------")
    print("Resultados de DNS Encontrados:")
    print("-------------------------")

    if not subdominios_encontrados:
        print("Nenhum subdomínio de DNS encontrado.")
    else:
        with open("dns_results.txt", "w", encoding='utf-8') as f:
            for sub, reg, tp in subdominios_encontrados:
                tipo_amigavel = tipo_traducao.get(tp, tp)
                linha = f"{sub} - {reg} ({tipo_amigavel})"
                print(linha)
                f.write(linha + "\n")

    print(f"\nTempo de execução da busca de DNS: {end_time - start_time:.2f} segundos.")

    if subdominios_encontrados:
        continuar = input("\nDeseja verificar se os subdomínios encontrados estão online? (s/n): ").lower()
        if continuar == 's':
            print("\nIniciando a busca de HTTP/HTTPS...")
            start_time = time.time()

            session = requests.Session()
            adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=Retry(total=1, backoff_factor=0.2))
            session.mount("http://", adapter)
            session.mount("https://", adapter)

            resultados_http = []

            host_to_ip = {s[0]: s[1] for s in subdominios_encontrados if s[1]}

            with concurrent.futures.ThreadPoolExecutor(max_workers=http_workers) as executor:
                futures = {
                    executor.submit(verificar_http, host, host_to_ip.get(host, None), session, HTTP_TIMEOUT): host
                    for host, _, _ in subdominios_encontrados
                }

                for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="HTTP", unit="req"):
                    try:
                        resultado = future.result()
                        if resultado:
                            resultados_http.extend(resultado)
                    except Exception:
                        pass

            end_time = time.time()

            print("\n----------------------------------")
            print("Resultados de HTTP/HTTPS Encontrados:")
            print("----------------------------------")

            if not resultados_http:
                print("Nenhum subdomínio está online.")
            else:
                with open("alive_subs_ips.txt", "w", encoding='utf-8') as f:
                    for url, status, protocol, ip in resultados_http:
                        linha = f"{url} - {status} [{ip}]"
                        print(linha)
                        f.write(linha + "\n")

            print(f"\nTempo de execução da busca HTTP/HTTPS: {end_time - start_time:.2f} segundos.")

if __name__ == "__main__":
    main()
