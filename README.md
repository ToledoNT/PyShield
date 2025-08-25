PyShield Firewall 🔒

Um firewall simples em Python para proteger sua rede.
O que ele faz?

    Bloqueia IPs indesejados

    Filtra portas e protocolos

    Mostra logs em tempo real

    Interface fácil de usar

📦 Instalação Fácil
bash

# Baixe e instale automaticamente
git clone https://github.com/ToledoNT/PyShield.git
cd PyShield
chmod +x install.sh
sudo ./install.sh

🚀 Como usar
bash

# Execute o firewall
sudo ./firewall.py

🎮 Menu Principal

Digite um número para escolher:
text

1 - Ver regras atuais
2 - Bloquear um IP
3 - Desbloquear um IP  
4 - Bloquear uma porta
5 - Desbloquear uma porta
6 - Recarregar regras
7 - Ver logs ao vivo
8 - Mudar nível de logs
9 - Sair

⚠️ Importante

    Precisa executar como sudo

    Funciona apenas no Linux

    Faz backup das suas regras antes de instalar

📊 O que vem por padrão?

✅ Portas permitidas: 80, 443, 53, 22 (web, https, dns, ssh)
✅ IPs liberados: localhost e 127.0.0.1
✅ Protocolos: TCP e UDP permitidos, ICMP bloqueado
🔧 Se precisar de ajuda

Verifique se tem tudo instalado:
bash

python3 --version
pip3 --version
sudo iptables --version

📁 Arquivos importantes

    firewall.py - Programa principal

    rules.json - Configurações das regras

    firewall.log - Arquivo de logs

    install.sh - Instalador automático

❓ Dúvidas comuns

P: Como volto para o menu?
R: Na tela de logs, pressione ENTER

P: Onde vejo as regras?
R: Opção 1 no menu

P: Como sair do programa?
R: Opção 9 ou Ctrl+C

⭐ Fácil de usar - Apenas execute e escolha as opções!