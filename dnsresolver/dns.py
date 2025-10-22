import subprocess
import shutil
import os
import json

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
    pass

def have_bin(name):
    bin_path = shutil.which(name)
    if not bin_path:
        local_path = os.path.join(os.getcwd(), name)
        if os.path.exists(local_path):
            bin_path = local_path
    return bin_path

def run_recon_pipeline(domain, timeout=300):
    

    subfinder_path = have_bin("subfinder")
    dnsx_path = have_bin("dnsx")

    if not subfinder_path:
        print("[subfinder] não encontrado no PATH. Pulando.")
        return []
    if not dnsx_path:
        print("[dnsx] não encontrado no PATH. Pulando.")
        return []

    
    subfinder_cmd = [subfinder_path, "-d", domain, "-silent"]
    
    dnsx_cmd = [dnsx_path, "-l", "-", "-o", "jinja.txt", "-recon",]

    try:
        
        subfinder_proc = subprocess.Popen(subfinder_cmd, stdout=subprocess.PIPE, text=True)
        
        dnsx_proc = subprocess.run(dnsx_cmd, stdin=subfinder_proc.stdout, capture_output=True, text=True, timeout=timeout)

        
        subfinder_proc.stdout.close()

        stdout = dnsx_proc.stdout or ""
        lines = [line.strip() for line in stdout.splitlines() if line.strip()]

        return lines
    except subprocess.TimeoutExpired:
        print("[Recon Pipeline] timeout expirado.")
        return []
    except Exception as e:
        print(f"[Recon Pipeline] erro: {e}")
        return []


if __name__ == "__main__":

    limpar_console()
    print(title)

    target = input("Domain name:")
    hosts = run_recon_pipeline(target)
    
    if hosts:
        print("Encontrados (saída JSON):", len(hosts))
        for host in hosts: 
            print(host)
    else:
        print("Nenhum host encontrado.")
    
  
