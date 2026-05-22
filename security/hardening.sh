#!/bin/bash
#
# Linux Hardening Validation Script
# Autor: ChatGPT
# Objetivo:
# Validar itens básicos de hardening em servidores Linux
#
# Compatível com:
# Ubuntu / Debian / CentOS / Rocky / AlmaLinux
#
# Execute como root:
# sudo bash hardening_check.sh
#

GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
BLUE="\e[34m"
END="\e[0m"

PASS="${GREEN}[OK]${END}"
FAIL="${RED}[FAIL]${END}"
WARN="${YELLOW}[WARN]${END}"
INFO="${BLUE}[INFO]${END}"

clear

echo -e "${BLUE}"
echo "====================================================="
echo "      LINUX SERVER HARDENING VALIDATION SCRIPT"
echo "====================================================="
echo -e "${END}"

##############################
# Função de validação
##############################
check() {
    if eval "$2" &>/dev/null; then
        echo -e "$PASS $1"
    else
        echo -e "$FAIL $1"
    fi
}

##############################
# 1. Atualizações
##############################
echo
echo "1. VALIDANDO ATUALIZAÇÕES"

if command -v apt >/dev/null 2>&1; then
    updates=$(apt list --upgradable 2>/dev/null | wc -l)

    if [ "$updates" -gt 1 ]; then
        echo -e "$WARN Existem pacotes pendentes de atualização"
    else
        echo -e "$PASS Sistema atualizado"
    fi
fi

if command -v yum >/dev/null 2>&1; then
    yum check-update >/dev/null 2>&1

    if [ $? -eq 100 ]; then
        echo -e "$WARN Existem atualizações pendentes"
    else
        echo -e "$PASS Sistema atualizado"
    fi
fi

##############################
# 2. Firewall
##############################
echo
echo "2. VALIDANDO FIREWALL"

if systemctl is-active ufw >/dev/null 2>&1; then
    echo -e "$PASS UFW ativo"

    check "Default deny incoming configurado" \
    "ufw status verbose | grep -i 'Default: deny (incoming)'"

elif systemctl is-active firewalld >/dev/null 2>&1; then
    echo -e "$PASS Firewalld ativo"

else
    echo -e "$FAIL Nenhum firewall ativo"
fi

##############################
# 3. SSH Root Login
##############################
echo
echo "3. VALIDANDO SSH ROOT LOGIN"

check "Root login desabilitado" \
"grep -Ei '^PermitRootLogin no' /etc/ssh/sshd_config"

##############################
# 4. Password Authentication
##############################
echo
echo "4. VALIDANDO AUTENTICAÇÃO SSH"

check "PasswordAuthentication desabilitado" \
"grep -Ei '^PasswordAuthentication no' /etc/ssh/sshd_config"

check "ChallengeResponseAuthentication desabilitado" \
"grep -Ei '^ChallengeResponseAuthentication no' /etc/ssh/sshd_config"

##############################
# 5. Fail2Ban
##############################
echo
echo "5. VALIDANDO FAIL2BAN"

if systemctl is-active fail2ban >/dev/null 2>&1; then
    echo -e "$PASS Fail2Ban ativo"

    fail2ban-client status sshd >/dev/null 2>&1

    if [ $? -eq 0 ]; then
        echo -e "$PASS Jail SSHD configurada"
    else
        echo -e "$WARN Jail SSHD não encontrada"
    fi
else
    echo -e "$FAIL Fail2Ban não está ativo"
fi

##############################
# 6. Serviços desnecessários
##############################
echo
echo "6. VALIDANDO SERVIÇOS DESNECESSÁRIOS"

services=(
telnet
vsftpd
rsh
rlogin
rexec
xinetd
)

for svc in "${services[@]}"
do
    if systemctl is-enabled $svc >/dev/null 2>&1; then
        echo -e "$FAIL Serviço inseguro habilitado: $svc"
    else
        echo -e "$PASS Serviço não habilitado: $svc"
    fi
done

##############################
# 7. Permissões inseguras
##############################
echo
echo "7. VALIDANDO PERMISSÕES INSEGURAS"

world_writable=$(find / -xdev -type f -perm -0002 2>/dev/null | wc -l)

if [ "$world_writable" -gt 0 ]; then
    echo -e "$WARN Arquivos world-writable encontrados: $world_writable"
else
    echo -e "$PASS Nenhum arquivo world-writable"
fi

##############################
# 8. Portas abertas
##############################
echo
echo "8. VALIDANDO PORTAS ABERTAS"

echo -e "${INFO} Portas em escuta:"
ss -tulnp

##############################
# 9. Logs
##############################
echo
echo "9. VALIDANDO LOGS"

if systemctl is-active rsyslog >/dev/null 2>&1; then
    echo -e "$PASS rsyslog ativo"
else
    echo -e "$WARN rsyslog não está ativo"
fi

if [ -f /var/log/auth.log ] || [ -f /var/log/secure ]; then
    echo -e "$PASS Logs de autenticação encontrados"
else
    echo -e "$FAIL Logs de autenticação ausentes"
fi

##############################
# 10. Backup
##############################
echo
echo "10. VALIDANDO BACKUPS"

if [ -d /backup ] || [ -d /backups ]; then
    echo -e "$PASS Diretório de backup encontrado"
else
    echo -e "$WARN Diretório de backup não encontrado"
fi

##############################
# 11. SELinux / AppArmor
##############################
echo
echo "11. VALIDANDO SELINUX / APPARMOR"

if command -v sestatus >/dev/null 2>&1; then
    if sestatus | grep -i "SELinux status" | grep enabled >/dev/null; then
        echo -e "$PASS SELinux habilitado"
    else
        echo -e "$WARN SELinux desabilitado"
    fi
fi

if command -v aa-status >/dev/null 2>&1; then
    if aa-status --enabled >/dev/null 2>&1; then
        echo -e "$PASS AppArmor habilitado"
    else
        echo -e "$WARN AppArmor desabilitado"
    fi
fi

##############################
# 12. Senhas vazias
##############################
echo
echo "12. VALIDANDO CONTAS COM SENHA VAZIA"

empty_pass=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null)

if [ -z "$empty_pass" ]; then
    echo -e "$PASS Nenhuma conta com senha vazia"
else
    echo -e "$FAIL Contas com senha vazia:"
    echo "$empty_pass"
fi

##############################
# 13. Usuários UID 0
##############################
echo
echo "13. VALIDANDO USUÁRIOS UID 0"

uid0=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)

echo "$uid0"

count=$(echo "$uid0" | wc -l)

if [ "$count" -eq 1 ]; then
    echo -e "$PASS Apenas root possui UID 0"
else
    echo -e "$WARN Existem múltiplos usuários com UID 0"
fi

##############################
# 14. Histórico sudo
##############################
echo
echo "14. VALIDANDO USO DE SUDO"

check "Pacote sudo instalado" \
"command -v sudo"

##############################
# FINAL
##############################
echo
echo -e "${BLUE}====================================================="
echo "           VALIDAÇÃO FINALIZADA"
echo -e "=====================================================${END}"
