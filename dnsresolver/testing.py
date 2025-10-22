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
    os.system('cls' if os.name == 'nt' else 'clear')

def have_bin(name):
    """Verifica se o binário existe no PATH ou no diretório local."""
    bin_path = shutil.which(name)
    if not bin_path:
        local_path = os.path.join(os.getcwd(), name)
        if os.path.exists(local_path):
            bin_path = local_path
    return bin_path

def run_recon_pipeline(domain, timeout=3000):
    subfinder_path = have_bin("subfinder")
    alterx_path = have_bin("alterx")
    dnsx_path = have_bin("dnsx")

    if not subfinder_path:
        print("[subfinder] não encontrado no PATH. Pulando.")
        return []
    if not alterx_path:
        print("[alterx] não encontrado no PATH. Pulando.")
        return []
    if not dnsx_path:
        print("[dnsx] não encontrado no PATH. Pulando.")
        return []

    subfinder_cmd = [subfinder_path, "-d", domain, "-silent"]
    alterx_cmd = [alterx_path, "-silent"]
    dnsx_cmd = [dnsx_path, "-l", "-", "-j", "-recon"]

    try:
        # subfinder → alterx → dnsx (encadeado por pipes)
        subfinder_proc = subprocess.Popen(subfinder_cmd, stdout=subprocess.PIPE, text=True)
        alterx_proc = subprocess.Popen(alterx_cmd, stdin=subfinder_proc.stdout, stdout=subprocess.PIPE, text=True)
        subfinder_proc.stdout.close()

        dnsx_proc = subprocess.run(
            dnsx_cmd,
            stdin=alterx_proc.stdout,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        alterx_proc.stdout.close()

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

def print_hosts_filtered(hosts):
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

if __name__ == "__main__":
    limpar_console()
    print(title)

    target = input("Domain name: ").strip()
    if not target:
        print("Nenhum domínio informado.")
        exit(1)

    hosts = run_recon_pipeline(target)

    safe_name = re.sub(r'[^A-Za-z0-9._-]', '_', target)
    output_filename = f"{safe_name}.json"
    try:
        with open(output_filename, "w", encoding="utf-8") as f:
            json.dump(hosts, f, ensure_ascii=False, indent=2)
        print(f"Resultado salvo em: {output_filename}")
    except Exception as e:
        print(f"Erro ao salvar arquivo: {e}")

    print_hosts_filtered(hosts)
