# SEU CÓDIGO AQUI
# netlas_scanner_fixed.py

import os
import re
import sys
import json
import socket
import netlas
from netlas import helpers

def is_ipv4(s: str) -> bool:
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s) is not None

def resolve_to_ip(target):
    if is_ipv4(target):
        return target
    try:
        ip_address = socket.gethostbyname(target)
        print(f"[DNS] {target} -> {ip_address}")
        return ip_address
    except socket.gaierror:
        print(f"ERRO: Não foi possível resolver: {target}")
        return None

def scan_netlas_and_save(target):
    ip_or_domain = target.strip()
    # Tenta ler API key do ambiente usando helper (procura em saved key ou variável)
    api_key = netlas.helpers.get_api_key() or os.getenv("NETLAS_API_KEY")
    if not api_key:
        print("ERRO: NETLAS_API_KEY não encontrada. Defina a variável de ambiente ou salve com `netlas savekey`.")
        return

    client = netlas.Netlas(api_key=api_key)

    # Se for domínio, pesquisamos por host:domain (retorna apenas responses web), para ip usamos host:IP
    if is_ipv4(ip_or_domain):
        query = f"host:{ip_or_domain}"
    else:
        # Tentamos tanto host:domínio quanto resolver para ip e pesquisar por ip
        ip_resolved = resolve_to_ip(ip_or_domain)
        if ip_resolved:
            query = f"host:{ip_resolved}"
        else:
            query = f"host:{ip_or_domain}"

    print(f"[NETLAS] Executando query: {query}")

    try:
        # Algumas versões da biblioteca Netlas não aceitam o parâmetro 'limit';
        # faça a consulta sem 'limit' e aplique limitação localmente.
        result = client.query(query=query, datatype="response")
    except Exception as e:
        print("ERRO na consulta Netlas:", e)
    # Alguns clientes/netlas podem retornar uma string JSON — tentar desserializar
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except json.JSONDecodeError:
            print("ERRO: resposta Netlas não é JSON válido.")
            return

    # Normalizar items: aceitar dict com "items" ou lista direta
    if isinstance(result, dict):
        items = result.get("items", [])
    elif isinstance(result, list):
        items = result
    else:
        print("ERRO: formato de resposta Netlas inesperado.")
        return

    # Limitar resultados localmente (algumas versões da biblioteca não aceitam 'limit')
    max_results = 50
    if isinstance(items, list):
        items = items[:max_results]

    if not items:
        print("[AVISO] Nenhum resultado encontrado.")
        return

    # Monta relatório resumido
    first_entry = items[0]
    # 'data' pode ser dict ou string JSON; normalizar
    data_field = first_entry.get('data') if isinstance(first_entry, dict) else None
    if isinstance(data_field, str):
        try:
            data_field = json.loads(data_field)
        except json.JSONDecodeError:
            data_field = None

    ip_key = None
    if isinstance(data_field, dict):
        ip_key = data_field.get('ip') or data_field.get('ip_address')
    # fallback para casos onde item já é um dict com 'ip' no topo
    if not ip_key:
        ip_key = first_entry.get('ip') if isinstance(first_entry, dict) else None
    out_filename = f"netlas_report_{(ip_key or 'unknown').replace('.', '_')}.json"

    summary = {
        "target": target,
        "query": query,
        "found_items": len(items),
        "first_item_sample": {}
    }

    # Preenche sample com campos úteis (ip, port, protocol, path, title, first_seen, last_seen, geo, asn)
    first = data_field if isinstance(data_field, dict) else (first_entry if isinstance(first_entry, dict) else {})
    summary['first_item_sample'] = {
        "ip": first.get('ip') if isinstance(first, dict) else None,
        "port": first.get('port') if isinstance(first, dict) else None,
        "protocol": first.get('protocol') if isinstance(first, dict) else None,
        "path": first.get('path') if isinstance(first, dict) else None,
        "title": first.get('title') if isinstance(first, dict) else None,
        "first_seen": first.get('first_seen') if isinstance(first, dict) else None,
        "last_seen": first.get('last_seen') if isinstance(first, dict) else None,
        "host_type": first.get('host_type') if isinstance(first, dict) else None,
    }

    # Tenta pegar portas únicas
    ports = sorted({(it.get('data') and (it['data'].get('port') if isinstance(it['data'], dict) else None)) or it.get('port')
                    for it in items if isinstance(it, dict)})
    ports = [p for p in ports if p]
    summary['ports_found'] = ports

    try:
        with open(out_filename, 'w', encoding='utf-8') as f:
            json.dump({"summary": summary, "raw_items": items}, f, ensure_ascii=False, indent=2)
        print(f"[SUCESSO] Relatório salvo em: {out_filename}")
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    except Exception as e:
        print("ERRO ao salvar relatório:", e)

if __name__ == "__main__":
    if len(sys.argv) >= 2:
        target = sys.argv[1]
    else:
        target = input("IP ou domínio: ").strip()
    if not target:
        print("Nenhum alvo fornecido.")
        sys.exit(1)
    scan_netlas_and_save(target)
