#!/bin/bash
MYIP=$(wget -qO- ipinfo.io/ip);

IZIN=$(curl -sS https://raw.githubusercontent.com/kiryudekei/izinvps/main/ip | awk '{print $4}' | grep $MYIP)
if [ $MYIP = $IZIN ]; then
echo "IZIN DI TERIMA!!"
else
clear
figlet "Akses di tolak!! Silakan Hubungi Admin" | lolcat
exit 0
fi

#install
cp /media/cybervpn/var.txt /tmp

clear

cp /root/cybervpn/var.txt /tmp

clear

rm -rf cybervpn

clear

apt update && apt upgrade -y
apt install python3 python3-pip -y
apt install sqlite3 -y
cd /media/
rm -rf cybervpn

clear

wget https://raw.githubusercontent.com/kiryusekei/v7/main/limit/cybervpn.zip
unzip cybervpn.zip
cd cybervpn
rm var.txt

clear

rm database.db

clear
# Install dependencies
apt update && apt upgrade -y
apt install python3 python3-pip git python3-venv -y

# Set up a virtual environment
cd /usr/bin
# Set up a virtual environment
python3 -m venv /media/cybervpn/venv

# Activate the virtual environment and install dependencies
source /media/cybervpn/venv/bin/activate
pip install telethon
pip install pillow
pip install speedtest-cli
pip3 install aiohttp
pip3 install paramiko
pip install -r /media/cybervpn/requirements.txt
deactivate
#isi data
sldns=$(cat /root/nsdomain)
domain=$(cat /etc/xray/domain)
clear
echo -e ""
echo -e ""
echo "INSTALL BOT CREATE SSH via TELEGRAM"
read -e -p "[*] Input Your Id Telegram :" admin
read -e -p "[*] Input Your bot Telegram :" token
read -e -p "[*] Input username Telegram :" user

cat > /media/cybervpn/var.txt << END
ADMIN="$admin"
BOT_TOKEN="$token"
DOMAIN="$domain"
DNS="$sldns"
PUB="7fbd1f8aa0abfe15a7903e837f78aba39cf61d36f183bd604daa2fe4ef3b7b59"
OWN="$user"
SALDO="100000"
END


clear
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[44;97;1m          ZERO TUNNELING          \e[0m"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[44;97;1m     CREATE BOT SUCCESFULLY        \e[0m"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[96;1m Api Token     : $token"
echo -e "\e[96;1m ID Telegram   : $admin"
echo -e "\e[96;1m Domain vps    : $domain"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
echo -e "\e91;1m Wait in 4 second.....\e[0m"
sleep 4
clear

rm -f /usr/bin/nenen

echo -e '#!/bin/bash\ncd /media/\npython3 -m cybervpn' > /usr/bin/nenen


chmod 777 /usr/bin/nenen

# Create the systemd service
cat > /etc/systemd/system/botrs.service << END
[Unit]
Description=Simple kyt - @kyt
After=network.target

[Service]
WorkingDirectory=/media
ExecStart=/media/cybervpn/venv/bin/python3 -m cybervpn
Restart=always

[Install]
WantedBy=multi-user.target
END

# Start and enable the service
systemctl start botrs
systemctl enable botrs
systemctl restart botrs

# Clean up
cd /root
rm -rf botrs.sh

clear
echo
echo
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[44;97;1m        DOWNLOAD ASSET BOT         \e[0m"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""

wget -q -O /usr/bin/panelbot "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/panelbot.sh" && chmod +x /usr/bin/panelbot

wget -q -O /usr/bin/addnoobz "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/addnoobz.sh" && chmod +x /usr/bin/addnoobz

wget -q -O /media/log-install.txt "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/log-install.txt"

wget -q -O /usr/bin/add-vless "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/add-vless.sh" && chmod +x /usr/bin/add-vless

wget -q -O /usr/bin/addtr "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/addtr.sh" && chmod +x /usr/bin/addtr

wget -q -O /usr/bin/addws "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/addws.sh" && chmod +x /usr/bin/addws

wget -q -O /usr/bin/addss "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/addss.sh" && chmod +x /usr/bin/addss

wget -q -O /usr/bin/cek-ssh "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/cek-ssh.sh" && chmod +x /usr/bin/cek-ssh

wget -q -O /usr/bin/cek-ss "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/cek-ss.sh" && chmod +x /usr/bin/cek-ss

wget -q -O /usr/bin/cek-tr "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/cek-tr.sh" && chmod +x /usr/bin/cek-tr

wget -q -O /usr/bin/cek-vless "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/cek-vless.sh" && chmod +x /usr/bin/cek-vless

wget -q -O /usr/bin/cek-ws "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/cek-ws.sh" && chmod +x /usr/bin/cek-ws

wget -q -O /usr/bin/del-vless "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/del-vless.sh" && chmod +x /usr/bin/del-vless

wget -q -O /usr/bin/cek-noobz "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/cek-noobz.sh" && chmod +x /usr/bin/cek-noobz

wget -q -O /usr/bin/deltr "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/deltr.sh" && chmod +x /usr/bin/deltr

wget -q -O /usr/bin/delws "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/delws.sh" && chmod +x /usr/bin/delws

wget -q -O /usr/bin/delss "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/delss.sh" && chmod +x /usr/bin/delss

wget -q -O /usr/bin/renew-ss "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/renew-ss.sh" && chmod +x /usr/bin/renew-ss

wget -q -O /usr/bin/renewtr "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/renewtr.sh" && chmod +x /usr/bin/renewtr

wget -q -O /usr/bin/renewvless "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/renewvless.sh" && chmod +x /usr/bin/renewvless

wget -q -O /usr/bin/renewws "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/renewws.sh" && chmod +x /usr/bin/renewws

wget -q -O /usr/bin/cek-mws "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/cek-mws.sh" && chmod +x /usr/bin/cek-mws

wget -q -O /usr/bin/cek-mvs "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/cek-mvs.sh" && chmod +x /usr/bin/cek-mvs

wget -q -O /usr/bin/cek-mss "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/cek-mss.sh" && chmod +x /usr/bin/cek-mss

wget -q -O /usr/bin/cek-mts "https://raw.githubusercontent.com/arivpnstores/v6/main/bot/cek-mts.sh" && chmod +x /usr/bin/cek-mts
wget -q -O /usr/bin/addssh-bot "http://myrid.my.id/bot/addssh-bot" && chmod +x /usr/bin/addssh-bot
cp /tmp/var.txt /media/cybervpn

clear

echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[44;97;1m          ZERO TUNNELING          \e[0m"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[44;97;1m       DOWNLOAD SUCCESFULLY        \e[0m"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
echo -e "\e[96;1m KETIK /menu : .menu : .crot : .gas DI BOT TELEGRAM ANDA \e[0m"
echo -e ""

rm /media/cybervpn.zip


exec bash
