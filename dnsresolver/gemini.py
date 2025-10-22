import subprocess
import shutil
import os
import json
import re
import sqlite3 # Adição necessária

title = """
$$$$$$$\                      $$$$$$$\                                $$\                                
$$  __$$\                     $$  __$$\                               $$ |                               
$$ |  $$ |$$$$$$$\   $$$$$$$\ $$ |  $$ | $$$$$$\   $$$$$$$\  $$$$$$\  $$ |$$\    $$\  $$$$$$\   $$$$$$\  
$$ |  $$ |$$  __$$\ $$  _____|$$$$$$$  |$$  __$$\ $$  _____|$$  __$$\ $$ |\$$\  $$  |$$  __$$\ $$  __$$\ 
$$ |  $$ |$$ |  $$ |\$$$$$$\  $$  __$$< $$$$$$$$ |\$$$$$$\  $$ /  $$ |$$ | \$$\$$  / $$$$$$$$ |$$ |  \__|
$$ |  $$ |$$ |  $$ | \____$$\ $$ |  $$ |$$   ____| \____$$\ $$ |  $$ |$$ |  \$$$  /  $$   ____|$$ |      
$$$$$$$  |$$ |  $$ |$$$$$$$  |$$ |  $$ |\$$$$$$$\ $$$$$$$  |\$$$$$$  |$$ |   \$  /   \$$$$$$$\ $$ |      
\_______/ \__|  \__|\_______/ \__|  \__| \_______|\_______/  \______/ \__|    \_/     \_______|\__|

"""

def limpar_console():
    # Implementação de limpeza que você já tinha (ajustada para cross-platform)
    if os.name == 'nt':
        os.system('cls') # Windows
    else:
        os.system('clear') # Linux/macOS

def setup_db(db_name="recon_results.db"):
    """Cria a conexão e a tabela de subdomínios, se não existirem."""
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    
    # DDL: Cria a tabela para armazenar os dados do DNSX
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS subdomains (
        id INTEGER PRIMARY KEY,
        domain_target TEXT NOT NULL,
        host TEXT NOT NULL UNIQUE,
        ipv4 TEXT,
        cname TEXT
    );
    """
    
    cursor.execute(create_table_sql)
    conn.commit()
    return conn, cursor


def insert_data_to_db(conn, cursor, hosts, target_domain):
    """Mapeia os dados JSON para colunas SQL e insere na tabela."""
    insert_sql = """
    INSERT OR IGNORE INTO subdomains (domain_target, host, ipv4, cname) 
    VALUES (?, ?, ?, ?)
    """
    
    for entry in hosts:
        host = entry.get("host", "")
        
        # Converte a lista de IPv4 para string: "IP1, IP2"
        ipv4_str = ", ".join(entry.get("a", [])) 
        
        # Converte a lista de CNAMEs para string: "cname1, cname2"
        cname_str = ", ".join(entry.get("cname", []))
        
        # Prepara a tupla de dados para inserção
        data_to_insert = (target_domain, host, ipv4_str, cname_str)
        
        # Executa a inserção
        cursor.execute(insert_sql, data_to_insert)
        
    conn.commit()
    print(f"\n[SQLite] {len(hosts)} hosts inseridos/atualizados no banco de dados.")


def have_bin(name):
    bin_path = shutil.which(name)
    if not bin_path:
        local_path = os.path.join(os.getcwd(), name)
        if os.path.exists(local_path):
            bin_path = local_path
    return bin_path

def run_recon_pipeline(domain, timeout=3000):
    subfinder_path = have_bin("subfinder")
    dnsx_path = have_bin("dnsx")

    if not subfinder_path:
        print("[subfinder] não encontrado no PATH. Pulando.")
        return []
    if not dnsx_path:
        print("[dnsx] não encontrado no PATH. Pulando.")
        return []

    subfinder_cmd = [subfinder_path, "-d", domain, "-silent"]
    # Atualizamos o DNSX para ter todos os flags de recon que havíamos discutido
    dnsx_cmd = [
        dnsx_path, 
        "-l", "-", 
        "-json",    # Flag JSON (mais robusto que -j)
        "-silent", 
        "-a",       # Resolve A records
        "-aaaa",    # Resolve AAAA records
        "-cname",   # Resolve CNAME records
        "-mx",      # Resolve MX records
        "-ns"       # Resolve Name Servers
    ]

    try:
        print(f"[Pipeline] Rodando subfinder no domínio: {domain}...")
        subfinder_proc = subprocess.Popen(subfinder_cmd, stdout=subprocess.PIPE, text=True)

        print("[Pipeline] Processando resultados com dnsx...")
        dnsx_proc = subprocess.run(
            dnsx_cmd,
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
                # Cada linha é um objeto JSON, usamos json.loads()
                obj = json.loads(line)
            except Exception:
                continue
            
            # Normalização e limpeza dos dados
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

    target = input("Domain name: ").strip()
    if not target:
        print("Nenhum domínio informado.")
        exit(1)

    hosts = run_recon_pipeline(target)

    # ----------------------------------------------------
    # BLOCO PRINCIPAL DO SQLITE
    # ----------------------------------------------------
    conn = None 
    try:
        # 1. Conecta ao banco de dados (cria o arquivo recon_results.db)
        conn, cursor = setup_db() 
        
        if hosts:
            # 2. Insere os dados dos hosts encontrados
            insert_data_to_db(conn, cursor, hosts, target)
            
    except sqlite3.Error as e:
        print(f"[SQLite] Erro ao operar o banco de dados: {e}")
    finally:
        # 3. Fecha a conexão
        if conn:
            conn.close()
    
    # ----------------------------------------------------
    # FINALIZAÇÃO: Imprimir resultados e salvar JSON
    # ----------------------------------------------------
    
    # Salva resultado em um arquivo .json (nome baseado no domínio, sanitizado)
    safe_name = re.sub(r'[^A-Za-z0-9._-]', '_', target)
    output_filename = f"{safe_name}.json"
    try:
        with open(output_filename, "w", encoding="utf-8") as f:
            json.dump(hosts, f, ensure_ascii=False, indent=2)
        print(f"Resultado salvo em arquivo JSON: {output_filename}")
    except Exception as e:
        print(f"Erro ao salvar arquivo JSON: {e}")


    def print_hosts_filtered(hosts):
        if not hosts:
            print("Nenhum resultado.")
            return

        print("\nResultados Detalhados:\n" + "=" * 40)
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

    print_hosts_filtered(hosts)