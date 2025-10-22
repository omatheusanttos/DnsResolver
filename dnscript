import subprocess
import shutil
import os
import json
import re

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

def limpar_console():
    os.system('cls')

def verificar_bin(name):
    bin_path = shutil.which(name)
    if not bin_path:
        local_path = os.path.join(os.getcwd(), name)
        if os.path.exists(local_path):
            bin_path = local_path
    return bin_path

def rodar_scanners(domain, timeout=3000):
    subfinder_path = verificar_bin("subfinder")
    dnsx_path = verificar_bin("dnsx")

    if not subfinder_path:
        print("[subfinder] não encontrado no PATH. Pulando.")
        return []
    if not dnsx_path:
        print("[dnsx] não encontrado no PATH. Pulando.")
        return []

    subfinder_comando = [subfinder_path, "-d", domain, "-silent"]
    dnsx_comando = [dnsx_path, "-l", "-", "-j", "-recon"]

    try:
        subfinder_proc = subprocess.Popen(subfinder_comando, stdout=subprocess.PIPE, text=True)

        dnsx_proc = subprocess.run(
            dnsx_comando,
            stdin=subfinder_proc.stdout,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        subfinder_proc.stdout.close()

        stdout = dnsx_proc.stdout or ""
        lines = [line.strip() for line in stdout.splitlines() if line.strip()]

        results = []
        for line in lines:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            entry = {
                "host": obj.get("host") or obj.get("Host") or "",
                "a": obj.get("a", []),
                "aaaa": obj.get("aaaa", []),
                "cname": obj.get("cname", []),
                "mx": obj.get("mx", []),
                "ns": obj.get("ns", [])
            }
            results.append(entry)

        return results
    except subprocess.TimeoutExpired:
        print("[Recon Pipeline] timeout expirado.")
        return []
    except Exception as e:
        print(f"[Recon Pipeline] erro: {e}")
        return []

if __name__ == "__main__":

    limpar_console()
    print(title)

    alvo = input("Nome do Domínio: ").strip()
    if not alvo:
        print("Nenhum domínio informado.")
        exit(1)

    hosts = rodar_scanners(alvo)

    
    safe_name = re.sub(r'[^A-Za-z0-9._-]', '_', alvo) # Função para salvar o resultado em um JSON
    output_filename = f"{safe_name}.json"
    try:
        with open(output_filename, "w", encoding="utf-8") as f:
            json.dump(hosts, f, ensure_ascii=False, indent=2)
        print(f"Resultado salvo em: {output_filename}")
    except Exception as e:
        print(f"Erro ao salvar arquivo: {e}")

    def exibirhosts_filtrado(hosts):
            if not hosts:
                print("Nenhum resultado.")
                return

            print("\nResultados:\n" + "=" * 40)
            for h in hosts:
                host = h.get("host") or h.get("Host") or "<unknown>"
                print(host)
                if h.get("a"):
                    print(f"  IPv4: {', '.join(h['a'])}")
                if h.get("aaaa"):
                    print(f"  IPv6: {', '.join(h['aaaa'])}")
                if h.get("cname"):
                    print(f"  CNAME: {', '.join(h['cname'])}")
                if h.get("mx"):
                    print(f"  MX: {', '.join(h['mx'])}")
                if h.get("ns"):
                    print(f"  Name Server: {', '.join(h['ns'])}")
                print()

    exibirhosts_filtrado(hosts)
