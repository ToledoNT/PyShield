#!/usr/bin/env python3
"""
PyShield Firewall - Firewall simples baseado em Python com Scapy
"""

import json
import os
import subprocess
import threading
import time
import signal
import sys
from datetime import datetime

# ---------------------- DEPENDÊNCIAS ---------------------- #
try:
    from termcolor import colored
except ImportError:
    print("Erro: Módulo 'termcolor' não instalado. Instale com: pip install termcolor")
    sys.exit(1)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except ImportError:
    print("Erro: Módulo 'scapy' não instalado. Instale com: pip install scapy")
    sys.exit(1)

# ---------------------- CONFIGURAÇÕES ---------------------- #
RULES_FILE = "rules.json"
LOG_FILE = "firewall.log"
UPDATE_INTERVAL = 300  # 5 minutos
ips_bloqueados_cache = set()  # Evita bloqueios repetidos
rules_manager = None  # Instância global para evitar recriação

# ---------------------- FUNÇÃO DE LOG ---------------------- #
def log_evento(msg, nivel="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"{timestamp} - {nivel} - {msg}"
    try:
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w", encoding='utf-8') as f:
                f.write("")  # cria arquivo vazio
        # Rotacionar log se estiver grande
        if os.path.getsize(LOG_FILE) > 10*1024*1024:
            backup = f"{LOG_FILE}.{datetime.now().strftime('%Y%m%d_%H%M%S')}.bak"
            os.rename(LOG_FILE, backup)
            with open(LOG_FILE, "w", encoding='utf-8') as f:
                f.write("")
        with open(LOG_FILE, "a", encoding='utf-8') as f:
            f.write(entry + "\n")
    except IOError as e:
        print(colored(f"Erro ao escrever log: {e}", "red"))

# ---------------------- GERENCIAMENTO DE REGRAS ---------------------- #
class FirewallRules:
    def __init__(self):
        self.rules = self.carregar_regras()
        self.last_update = time.time()
        self.lock = threading.Lock()

    def carregar_regras(self):
        default_rules = {
            "blocked_ips": [],
            "blocked_ports": [],
            "allowed_ports": [80, 443, 53, 22],
            "whitelist_ips": ["127.0.0.1", "localhost"],
            "protocol_rules": {"TCP": {"action": "allow"}, "UDP": {"action": "allow"}, "ICMP": {"action": "block"}},
            "log_level": "INFO"
        }
        try:
            if os.path.exists(RULES_FILE):
                with open(RULES_FILE, "r", encoding='utf-8') as f:
                    data = f.read().strip()
                    if data:
                        loaded = json.loads(data)
                        for k in default_rules:
                            if k not in loaded:
                                loaded[k] = default_rules[k]
                        return loaded
        except (json.JSONDecodeError, IOError) as e:
            print(colored(f"⚠️ Erro ao carregar regras: {e}. Usando padrão.", "yellow"))
            log_evento(f"Erro ao carregar regras: {e}", "ERROR")
        return default_rules

    def get_rules(self):
        with self.lock:
            if time.time() - self.last_update > UPDATE_INTERVAL:
                self.rules = self.carregar_regras()
                self.last_update = time.time()
                log_evento("Regras recarregadas automaticamente", "INFO")
            return self.rules.copy()

    def update_rules(self, new_rules):
        with self.lock:
            self.rules = new_rules
            self.last_update = time.time()
            self.salvar_regras(new_rules)
            log_evento("Regras atualizadas manualmente", "INFO")

    def salvar_regras(self, regras):
        try:
            with open(RULES_FILE, "w", encoding='utf-8') as f:
                json.dump(regras, f, indent=4, ensure_ascii=False)
        except IOError as e:
            print(colored(f"Erro ao salvar regras: {e}", "red"))
            log_evento(f"Erro ao salvar regras: {e}", "ERROR")

# ---------------------- BLOQUEIO DE IP ---------------------- #
def bloquear_ip(ip):
    if ip in ips_bloqueados_cache:
        return
    try:
        check_cmd = ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
        if subprocess.run(check_cmd, capture_output=True, text=True).returncode != 0:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            log_evento(f"IP {ip} bloqueado", "INFO")
        else:
            log_evento(f"IP {ip} já bloqueado", "INFO")
        ips_bloqueados_cache.add(ip)
    except subprocess.CalledProcessError as e:
        log_evento(f"Erro ao bloquear IP {ip}: {e}", "ERROR")
    except FileNotFoundError:
        log_evento("iptables não encontrado", "ERROR")

# ---------------------- ANÁLISE DE PACOTES ---------------------- #
def analisar_pacote(pacote):
    regras = rules_manager.get_rules()
    if not pacote.haslayer(IP):
        return
    ip_origem = pacote[IP].src
    if ip_origem in regras.get("whitelist_ips", []):
        return

    protocol, port = None, None
    if pacote.haslayer(TCP):
        protocol = "TCP"
        port = pacote[TCP].dport
    elif pacote.haslayer(UDP):
        protocol = "UDP"
        port = pacote[UDP].dport
    elif pacote.haslayer(ICMP):
        protocol = "ICMP"

    bloquear, msg = False, ""
    if ip_origem in regras["blocked_ips"]:
        bloquear, msg = True, f"Pacote de IP bloqueado: {ip_origem}"
    elif protocol and protocol in regras["protocol_rules"] and regras["protocol_rules"][protocol]["action"] == "block":
        bloquear, msg = True, f"Protocolo {protocol} bloqueado de {ip_origem}"
    elif port and port in regras["blocked_ports"]:
        bloquear, msg = True, f"Porta {port} bloqueada de {ip_origem}"
    elif port and regras.get("allowed_ports") and port not in regras["allowed_ports"]:
        bloquear, msg = True, f"Porta {port} não permitida de {ip_origem}"

    if bloquear:
        bloquear_ip(ip_origem)
        log_evento(msg, "WARNING")

# ---------------------- EXIBIÇÃO DE REGRAS ---------------------- #
def exibir_regras(regras):
    print(colored("\n=== REGRAS ATUAIS ===", "yellow"))
    print(colored("IPs Bloqueados:", "red"), *regras["blocked_ips"], sep="\n - ")
    print(colored("Portas Bloqueadas:", "red"), *regras["blocked_ports"], sep="\n - ")
    print(colored("Portas Permitidas:", "green"), *regras["allowed_ports"], sep="\n - ")
    print(colored("Whitelist de IPs:", "cyan"), *regras["whitelist_ips"], sep="\n - ")
    print(colored("Regras de Protocolos:", "magenta"))
    for proto, cfg in regras["protocol_rules"].items():
        print(f" - {proto}: {cfg['action']}")
    print(colored(f"Nível de log: {regras.get('log_level', 'INFO')}", "white"))

# ---------------------- INTERFACE ADMIN ---------------------- #
def interface_admin():
    global rules_manager
    while True:
        print("\n" + "="*50)
        print(colored("🔥 PyShield - Interface de Administração", "cyan"))
        print("1. Listar regras atuais")
        print("2. Adicionar IP bloqueado")
        print("3. Remover IP bloqueado")
        print("4. Adicionar porta bloqueada")
        print("5. Remover porta bloqueada")
        print("6. Recarregar regras")
        print("7. Visualizar logs em tempo real")
        print("8. Alterar nível de log")
        print("9. Sair")

        try:
            opcao = input("\nEscolha uma opção: ").strip()
            regras = rules_manager.get_rules()

            if opcao == "1":
                exibir_regras(regras)
            elif opcao == "2":
                ip = input("IP para bloquear: ").strip()
                if ip and ip not in regras["blocked_ips"]:
                    regras["blocked_ips"].append(ip)
                    rules_manager.update_rules(regras)
                    bloquear_ip(ip)
                    print(colored(f"IP {ip} bloqueado com sucesso!", "green"))
                else:
                    print(colored("IP inválido ou já bloqueado!", "red"))
            elif opcao == "3":
                ip = input("IP para desbloquear: ").strip()
                if ip and ip in regras["blocked_ips"]:
                    regras["blocked_ips"].remove(ip)
                    rules_manager.update_rules(regras)
                    ips_bloqueados_cache.discard(ip)
                    print(colored(f"IP {ip} removido da lista de bloqueio!", "green"))
                else:
                    print(colored("IP inválido ou não bloqueado!", "red"))
            elif opcao == "4":
                try:
                    porta = int(input("Porta para bloquear: ").strip())
                    if porta not in regras["blocked_ports"]:
                        regras["blocked_ports"].append(porta)
                        rules_manager.update_rules(regras)
                        print(colored(f"Porta {porta} bloqueada com sucesso!", "green"))
                    else:
                        print(colored("Porta já bloqueada!", "yellow"))
                except ValueError:
                    print(colored("Porta inválida!", "red"))
            elif opcao == "5":
                try:
                    porta = int(input("Porta para desbloquear: ").strip())
                    if porta in regras["blocked_ports"]:
                        regras["blocked_ports"].remove(porta)
                        rules_manager.update_rules(regras)
                        print(colored(f"Porta {porta} removida da lista de bloqueio!", "green"))
                    else:
                        print(colored("Porta não estava bloqueada!", "yellow"))
                except ValueError:
                    print(colored("Porta inválida!", "red"))
            elif opcao == "6":
                rules_manager.rules = rules_manager.carregar_regras()
                rules_manager.last_update = time.time()
                print(colored("Regras recarregadas com sucesso!", "green"))
            elif opcao == "7":
                exibir_logs_realtime()
            elif opcao == "8":
                nivel = input("Nível de log (DEBUG/INFO/WARNING/ERROR): ").strip().upper()
                if nivel in ["DEBUG", "INFO", "WARNING", "ERROR"]:
                    regras["log_level"] = nivel
                    rules_manager.update_rules(regras)
                    print(colored(f"Nível de log alterado para {nivel}!", "green"))
                else:
                    print(colored("Nível de log inválido!", "red"))
            elif opcao == "9":
                print(colored("Saindo da interface administrativa...", "yellow"))
                log_evento("Firewall encerrado pelo usuário", "INFO")
                break
            else:
                print(colored("Opção inválida!", "red"))

        except KeyboardInterrupt:
            print(colored("\nOperação cancelada pelo usuário", "yellow"))
            log_evento("Operação cancelada pelo usuário", "INFO")
            break
        except Exception as e:
            log_evento(f"Erro na interface admin: {e}", "ERROR")

# ---------------------- MAIN ---------------------- #
def main():
    global rules_manager
    if os.geteuid() != 0:
        print(colored("Execute como root! sudo python3 firewall.py", "red"))
        sys.exit(1)

    # Criar log vazio se não existir
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write("")

    rules_manager = FirewallRules()  # instância global única

    def signal_handler(sig, frame):
        print(colored("\n=== Encerrando PyShield Firewall ===", "yellow"))
        log_evento("Firewall encerrado via sinal", "INFO")
        os._exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(colored("=== PyShield Firewall Iniciado ===", "cyan"))
    log_evento("Firewall iniciado", "INFO")

    # Thread de captura de pacotes
    captura_thread = threading.Thread(target=lambda: sniff(prn=analisar_pacote, store=0, filter="ip"), daemon=True)
    captura_thread.start()

    # Interface administrativa
    interface_admin()

if __name__ == "__main__":
    main()