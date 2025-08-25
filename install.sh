#!/bin/bash
echo "Instalando PyShield Firewall..."
echo "Atualizando repositórios..."
sudo apt-get update

echo "Instalando dependências do sistema..."
sudo apt-get install -y python3 python3-pip iptables

echo "Instalando dependências Python..."
pip3 install scapy termcolor

echo "Configurando iptables (ATENÇÃO: isso limpa regras existentes)..."
sudo iptables -F
sudo iptables -P INPUT ACCEPT

echo "Dando permissões de execução..."
chmod +x firewall.py

echo "Instalação concluída!"
echo "Execute com: sudo ./firewall.py"