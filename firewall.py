#!/usr/bin/env python3
"""
PyShield Firewall - Sistema avançado de proteção baseado em Python
Logs sempre em append, thread-safe, e interface responsiva
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

# ---------------------- CONFIGURAÇÕES GLOBAIS ---------------------- #
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))  # pasta do script
CONFIG_DIR = SCRIPT_DIR
RULES_FILE = os.path.join(CONFIG_DIR, "rules.json")
LOG_FILE = os.path.join(CONFIG_DIR, "firewall.log")
UPDATE_INTERVAL = 300  # 5 minutos

ips_bloqueados_cache = set()
rules_manager = None
running = True
ver_logs = False
log_lock = threading.Lock()

# ---------------------- SISTEMA DE LOGS ---------------------- #
def log_evento(msg, nivel="INFO"):
    """Salva logs em arquivo thread-safe e exibe opcionalmente no console"""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"{timestamp} - {nivel} - {msg}"
        with log_lock:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(entry + "\n")
                f.flush()
        if ver_logs:
            print(colored(entry, "yellow"))
    except Exception as e:
        print(colored(f"ERRO CRÍTICO no sistema de logs: {e}", "red"), flush=True)

# ---------------------- GERENCIAMENTO DE REGRAS ---------------------- #
class FirewallRules:
    def __init__(self):
        self.lock = threading.Lock()
        self.rules = self.carregar_regras()
        self.last_update = time.time()
        log_evento("Gerenciador de regras inicializado", "DEBUG")

    def carregar_regras(self):
        if os.path.exists(RULES_FILE):
            try:
                with open(RULES_FILE, "r", encoding="utf-8") as f:
                    regras = json.load(f)
                    log_evento(f"Regras carregadas: {len(regras.get('blocked_ips', []))} IPs bloqueados", "DEBUG")
                    return regras
            except (json.JSONDecodeError, IOError) as e:
                log_evento(f"Erro ao carregar regras: {e}. Usando padrão.", "ERROR")
        return {
            "blocked_ips": [],
            "blocked_ports": [],
            "allowed_ports": [80, 443, 53, 22],
            "whitelist_ips": ["127.0.0.1", "localhost"],
            "protocol_rules": {"TCP": {"action": "allow"}, "UDP": {"action": "allow"}, "ICMP": {"action": "block"}},
            "log_level": "INFO",
            "max_log_size": 10
        }

    def get_rules(self):
        with self.lock:
            if time.time() - self.last_update > UPDATE_INTERVAL:
                self.rules = self.carregar_regras()
                self.last_update = time.time()
            return self.rules.copy()

    def update_rules(self, new_rules):
        with self.lock:
            self.rules = new_rules
            self.last_update = time.time()
            self.salvar_regras(new_rules)

    def salvar_regras(self, regras):
        try:
            with open(RULES_FILE, "w", encoding="utf-8") as f:
                json.dump(regras, f, indent=4, ensure_ascii=False)
            log_evento("Regras salvas com sucesso", "DEBUG")
        except IOError as e:
            log_evento(f"Erro ao salvar regras: {e}", "ERROR")

# ---------------------- INICIALIZAÇÃO DO SISTEMA ---------------------- #
def inicializar_sistema():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("\n" + "="*80 + "\n")
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - INFO - Sistema inicializado\n")
        f.write("="*80 + "\n")
    log_evento("Novo ciclo de execução iniciado (append)", "INFO")
    if not os.path.exists(RULES_FILE):
        regras_padrao = FirewallRules().carregar_regras()
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(regras_padrao, f, indent=4, ensure_ascii=False)
        log_evento("Arquivo de regras padrão criado", "INFO")

# ---------------------- FUNÇÕES DE BLOQUEIO ---------------------- #
def executar_iptables(comando):
    try:
        subprocess.run(comando, capture_output=True, text=True)
    except Exception as e:
        log_evento(f"Erro ao executar iptables: {e}", "ERROR")

def bloquear_ip(ip):
    if ip in ips_bloqueados_cache:
        return
    def worker():
        result = subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
        if result.returncode != 0:
            executar_iptables(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            log_evento(f"IP {ip} bloqueado", "INFO")
        ips_bloqueados_cache.add(ip)
    threading.Thread(target=worker, daemon=True).start()

def desbloquear_ip(ip):
    def worker():
        result = subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True)
        if result.returncode == 0:
            executar_iptables(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            log_evento(f"IP {ip} desbloqueado", "INFO")
        ips_bloqueados_cache.discard(ip)
    threading.Thread(target=worker, daemon=True).start()

def bloquear_porta(porta):
    def worker():
        result = subprocess.run(["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(porta), "-j", "DROP"], capture_output=True)
        if result.returncode != 0:
            executar_iptables(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(porta), "-j", "DROP"])
            log_evento(f"Porta {porta} bloqueada", "INFO")
    threading.Thread(target=worker, daemon=True).start()

def desbloquear_porta(porta):
    def worker():
        result = subprocess.run(["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(porta), "-j", "DROP"], capture_output=True)
        if result.returncode == 0:
            executar_iptables(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(porta), "-j", "DROP"])
            log_evento(f"Porta {porta} desbloqueada", "INFO")
    threading.Thread(target=worker, daemon=True).start()

# ---------------------- CAPTURA DE PACOTES ---------------------- #
def analisar_pacote(pkt):
    if not pkt.haslayer(IP):
        return
    regras = rules_manager.get_rules()
    ip_origem = pkt[IP].src
    if ip_origem in regras.get("whitelist_ips", []):
        return

    protocol, port = None, None
    if pkt.haslayer(TCP):
        protocol, port = "TCP", pkt[TCP].dport
    elif pkt.haslayer(UDP):
        protocol, port = "UDP", pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"

    motivo = None
    if ip_origem in regras["blocked_ips"]:
        motivo = f"IP bloqueado: {ip_origem}"
    elif protocol in regras.get("protocol_rules", {}) and regras["protocol_rules"][protocol]["action"] == "block":
        motivo = f"Protocolo {protocol} bloqueado de {ip_origem}"
    elif port in regras.get("blocked_ports", []):
        motivo = f"Porta {port} bloqueada de {ip_origem}"
    elif port and port not in regras.get("allowed_ports", []):
        motivo = f"Porta {port} não permitida de {ip_origem}"

    if motivo:
        bloquear_ip(ip_origem)
        log_evento(f"Bloqueio: {motivo}", "WARNING")

def captura_continua():
    while running:
        try:
            sniff(prn=analisar_pacote, store=0, filter="ip", timeout=1)
        except Exception as e:
            log_evento(f"Erro na captura: {e}", "ERROR")
            time.sleep(5)

# ---------------------- INTERFACE ADMIN ---------------------- #
def input_seguro(prompt):
    try:
        val = input(prompt)
        return val.strip() if val.strip() != "" else None
    except (KeyboardInterrupt, EOFError):
        print(colored("\nOperação cancelada", "yellow"))
        return None

def exibir_regras(regras):
    print(colored("\n=== REGRAS ATUAIS ===", "yellow", attrs=["bold"]))
    print(colored("IPs Bloqueados:", "red"), *(f" - {ip}" for ip in regras["blocked_ips"]) or [" - Nenhum"])
    print(colored("Portas Bloqueadas:", "red"), *(f" - {p}" for p in regras["blocked_ports"]) or [" - Nenhuma"])
    print(colored("Portas Permitidas:", "green"), *(f" - {p}" for p in regras["allowed_ports"]))
    print(colored("Whitelist de IPs:", "cyan"), *(f" - {ip}" for ip in regras["whitelist_ips"]) or [" - Nenhum"])
    print(colored("Protocolos:", "magenta"))
    for proto, cfg in regras["protocol_rules"].items():
        print(f" - {proto}: {cfg['action']}")

def exibir_logs_realtime():
    global ver_logs
    ver_logs = True
    print(colored("\n=== LOGS EM TEMPO REAL (Pressione Enter para voltar) ===", "cyan"))
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                for line in f.readlines()[-20:]:
                    print(colored(line.strip(), "yellow"))

        last_size = os.path.getsize(LOG_FILE) if os.path.exists(LOG_FILE) else 0

        while ver_logs:
            if os.path.exists(LOG_FILE):
                current_size = os.path.getsize(LOG_FILE)
                if current_size > last_size:
                    with open(LOG_FILE, "r", encoding="utf-8") as f:
                        f.seek(last_size)
                        for line in f.readlines():
                            print(colored(line.strip(), "yellow"))
                        last_size = f.tell()
            import select
            dr, _, _ = select.select([sys.stdin], [], [], 0.5)
            if dr:
                sys.stdin.readline()
                break
            time.sleep(0.5)
    finally:
        ver_logs = False
        print(colored("Voltando ao menu principal...", "green"))

# ---------------------- FUNÇÃO PRINCIPAL ---------------------- #
def interface_admin():
    global running, rules_manager
    while running:
        print("\n" + "="*50)
        print(colored("🔥 PyShield - Painel de Controle", "cyan", attrs=["bold"]))
        print("1. Listar regras\n2. Adicionar IP\n3. Remover IP\n4. Adicionar porta\n5. Remover porta\n6. Adicionar IP whitelist\n7. Remover IP whitelist\n8. Recarregar regras\n9. Ver logs\n0. Sair")
        opcao = input_seguro("\nEscolha uma opção: ")
        if opcao is None:
            continue
        regras = rules_manager.get_rules()
        if opcao == "1":
            exibir_regras(regras)
        elif opcao == "2":
            ip = input_seguro("IP para bloquear (Enter para voltar): ")
            if ip and ip not in regras["blocked_ips"]:
                regras["blocked_ips"].append(ip)
                rules_manager.update_rules(regras)
                bloquear_ip(ip)
                log_evento(f"IP {ip} adicionado à lista de bloqueio via interface", "INFO")
        elif opcao == "3":
            ip = input_seguro("IP para desbloquear (Enter para voltar): ")
            if ip and ip in regras["blocked_ips"]:
                regras["blocked_ips"].remove(ip)
                rules_manager.update_rules(regras)
                desbloquear_ip(ip)
                log_evento(f"IP {ip} removido da lista de bloqueio via interface", "INFO")
        elif opcao == "4":
            porta = input_seguro("Porta para bloquear (Enter para voltar): ")
            if porta and porta.isdigit() and int(porta) not in regras["blocked_ports"]:
                regras["blocked_ports"].append(int(porta))
                rules_manager.update_rules(regras)
                bloquear_porta(int(porta))
                log_evento(f"Porta {porta} adicionada à lista de bloqueio via interface", "INFO")
        elif opcao == "5":
            porta = input_seguro("Porta para desbloquear (Enter para voltar): ")
            if porta and porta.isdigit() and int(porta) in regras["blocked_ports"]:
                regras["blocked_ports"].remove(int(porta))
                rules_manager.update_rules(regras)
                desbloquear_porta(int(porta))
                log_evento(f"Porta {porta} removida da lista de bloqueio via interface", "INFO")
        elif opcao == "6":
            ip = input_seguro("IP para adicionar à whitelist (Enter para voltar): ")
            if ip and ip not in regras["whitelist_ips"]:
                regras["whitelist_ips"].append(ip)
                rules_manager.update_rules(regras)
                log_evento(f"IP {ip} adicionado à whitelist via interface", "INFO")
        elif opcao == "7":
            ip = input_seguro("IP para remover da whitelist (Enter para voltar): ")
            if ip and ip in regras["whitelist_ips"]:
                regras["whitelist_ips"].remove(ip)
                rules_manager.update_rules(regras)
                log_evento(f"IP {ip} removido da whitelist via interface", "INFO")
        elif opcao == "8":
            rules_manager = FirewallRules()
            print(colored("Regras recarregadas com sucesso!", "green"))
            log_evento("Regras recarregadas manualmente via interface", "INFO")
        elif opcao == "9":
            exibir_logs_realtime()
        elif opcao == "0":
            log_evento("Firewall encerrado pelo usuário", "INFO")
            print(colored("Encerrando PyShield Firewall...", "green"))
            running = False
        else:
            print(colored("Opção inválida!", "red"))
            log_evento(f"Tentativa de opção inválida na interface: {opcao}", "WARNING")

# ---------------------- MAIN ---------------------- #
def main():
    global rules_manager
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        print(colored("Execute como root para funcionalidades de rede!", "red"))
        sys.exit(1)

    inicializar_sistema()
    rules_manager = FirewallRules()

    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))

    threading.Thread(target=captura_continua, daemon=True).start()
    log_evento("🔥 PyShield Firewall inicializado com sucesso!", "INFO")
    print(colored("🔥 PyShield Firewall inicializado!", "green", attrs=["bold"]))
    interface_admin()
    log_evento("PyShield Firewall encerrado", "INFO")
    print(colored("PyShield Firewall encerrado.", "red"))

if __name__ == "__main__":
    main()
