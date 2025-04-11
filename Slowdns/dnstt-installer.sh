#!/bin/bash

BIN_NAME="dnstt-manager"
BIN_URL="https://github.com/kiritosshxd/SSHPLUS/raw/refs/heads/main/Slowdns/dnstt-manager"

echo "[+] Baixando $BIN_NAME..."
curl -sSL "$BIN_URL" -o "$BIN_NAME"

if [ ! -f "$BIN_NAME" ]; then
    echo "[ERRO] Falha ao baixar o binário."
    exit 1
fi

chmod +x "$BIN_NAME"
sudo mv "$BIN_NAME" /usr/local/bin/

echo "[✔] Instalação completa! Você pode executar com:"
echo "     dnstt-manager"
