# PyShield Firewall 🔒

Um firewall simples em Python para proteger sua rede.

## O que ele faz?

- Bloqueia IPs indesejados
- Filtra portas e protocolos
- Mostra logs em tempo real
- Interface fácil de usar

## 📦 Instalação Fácil

```bash
# Baixe o repositório
git clone https://github.com/ToledoNT/PyShield.git
cd PyShield

# Dê permissão e execute o instalador
chmod +x install.sh
sudo ./install.sh

    O instalador cria rules.json e firewall.log na mesma pasta do script.

🚀 Como usar

# Execute o firewall
sudo ./firewall.py

🎮 Menu Principal

Digite um número para escolher:

1 - Ver regras atuais
2 - Adicionar IP à lista de bloqueio
3 - Remover IP da lista de bloqueio
4 - Bloquear uma porta
5 - Desbloquear uma porta
6 - Adicionar IP à whitelist
7 - Remover IP da whitelist
8 - Recarregar regras
9 - Ver logs em tempo real
0 - Sair

⚠️ Importante

    Precisa executar como sudo.

    Funciona apenas no Linux.

    Recomenda-se fazer backup das suas regras antes de instalar.

📊 Configuração padrão

    ✅ Portas permitidas: 80, 443, 53, 22 (web, https, dns, ssh)

    ✅ IPs liberados: localhost e 127.0.0.1

    ✅ Protocolos: TCP e UDP permitidos, ICMP bloqueado

🔧 Verificação de dependências

Certifique-se de ter tudo instalado:

python3 --version
pip3 --version
sudo iptables --version
pip install scapy termcolor

📁 Arquivos importantes

    firewall.py - Programa principal

    rules.json - Configurações das regras

    firewall.log - Arquivo de logs

    install.sh - Instalador automático

⭐ Fácil de usar — Apenas execute e escolha as opções!