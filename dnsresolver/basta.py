import json
import os
from censys.search import CensysHosts
from censys.common.exceptions import (
    CensysUnauthorizedException, 
    CensysRateLimitExceededException, 
    CensysException
)

# AVISO: O código ABAIXO NÃO precisa do token embutido, pois ele 
# irá carregar as variáveis do seu terminal.

def scan_ip_and_save(ip_address):
    """
    Pesquisa um IP no Censys Search API (Hosts Index) e salva as principais 
    informações em um arquivo de texto.
    """
    
    # 1. Inicializa o cliente CensysHosts
    try:
        # AQUI É O PONTO CHAVE: Chama sem argumentos para carregar 
        # CENSYS_API_ID e CENSYS_API_SECRET das variáveis de ambiente.
        c = CensysHosts()
        
    except CensysUnauthorizedException:
        print("ERRO FATAL: Credenciais inválidas. As variáveis de ambiente CENSYS_API_ID e CENSYS_API_SECRET estão incorretas ou faltando.")
        return
    except Exception as e:
        print(f"ERRO ao inicializar o cliente Censys: {e}")
        return

    # 2. Faz a consulta (view) do IP
    print(f"\n[CENSYS] Pesquisando dados para o IP: {ip_address}...")
    try:
        host_data = c.view(ip_address)
        
    except CensysRateLimitExceededException:
        print("ERRO: Limite de taxa da API excedido. Tente novamente mais tarde.")
        return
    except CensysException as e:
        print(f"AVISO: O IP pode não ter sido encontrado no índice Hosts do Censys. Detalhe: {e}")
        return
    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")
        return

    # 3. Processa e salva as informações
    output_filename = f"censys_report_{ip_address.replace('.', '_')}.txt"
    
    try:
        # Extração de dados da estrutura do Censys Search
        location = host_data.get('location', {})
        country = location.get('country')
        city = location.get('city')
        
        asn = host_data.get('autonomous_system', {}).get('name')
        services = host_data.get('services', [])
        
        
        with open(output_filename, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write(f"RELATÓRIO CENSYS PARA IP: {ip_address}\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("--- INFORMAÇÕES GERAIS ---\n")
            f.write(f"Localização: {city or 'N/A'}, {country or 'N/A'}\n")
            f.write(f"AS (Organização): {asn or 'N/A'}\n")
            f.write(f"Última Atualização: {host_data.get('last_updated', 'N/A')}\n\n")
            
            f.write("--- SERVIÇOS/PORTAS ABERTAS ---\n")
            if services:
                for service in services:
                    port = service.get('port')
                    name = service.get('service_name')
                    f.write(f"  Porta {port}: {name}\n")
            else:
                f.write("  Nenhum serviço conhecido encontrado.\n")

            f.write("\n" + "=" * 60 + "\n")
            f.write("DADOS JSON BRUTOS (Para análise completa):\n")
            f.write("=" * 60 + "\n")
            
            f.write(json.dumps(host_data, indent=4, ensure_ascii=False))
            
        print(f"\n[SUCESSO] Relatório salvo em: {output_filename}")
        
    except Exception as e:
        print(f"ERRO ao processar e salvar os dados: {e}")


if __name__ == "__main__":
    
    # (Verificação do módulo omitida)
    
    print("--- CENSYS IP SCANNER (API TRADICIONAL) ---")
    target_ip = input("Digite o endereço IP (ex: 8.8.8.8): ").strip()

    if target_ip:
        scan_ip_and_save(target_ip)
    else:
        print("Nenhum IP fornecido. Encerrando.")