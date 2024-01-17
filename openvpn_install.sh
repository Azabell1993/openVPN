#!/bin/bash
#
# Azabell1993
#

# Debian 사용자가 "sh" 대신에 "bash"로 스크립트를 실행하는지 감지
if readlink /proc/$$/exe | grep -q "dash"; then
        echo '이 설치 프로그램은 "sh"가 아닌 "bash"로 실행되어야 합니다.'
        exit
fi

# stdin 폐기. 개행을 포함한 원 라이너에서 실행될 때 필요
read -N 999999 -t 0.001

# OpenVZ 6 감지
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
        echo "시스템은 오래된 커널을 실행하고 있어 이 설치 프로그램과 호환되지 않습니다."
        exit
fi

# 운영 체제 감지
# $os_version 변수는 항상 사용되지는 않지만 편의를 위해 여기에 유지
if grep -qs "ubuntu" /etc/os-release; then
        os="ubuntu"
        os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
        group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
        os="debian"
        os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
        group_name="nogroup"
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
        os="centos"
        os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
        group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
        os="fedora"
        os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
        group_name="nobody"
else
        echo "이 설치 프로그램은 지원되지 않는 배포판에서 실행되는 것으로 보입니다. 
	지원되는 배포판은 Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS 및 Fedora입니다."
        exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
        echo "이 설치 프로그램을 사용하려면 Ubuntu 18.04 이상이 필요합니다.
이 Ubuntu 버전은 너무 오래되어 더 이상 지원되지 않습니다."
        exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
        echo "이 설치 프로그램을 사용하려면 Debian 9 이상이 필요합니다.
이 Debian 버전은 너무 오래되어 더 이상 지원되지 않습니다."
        exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
        echo "이 설치 프로그램을 사용하려면 CentOS 7 이상이 필요합니다.
이 CentOS 버전은 너무 오래되어 더 이상 지원되지 않습니다."
        exit
fi

# $PATH에 sbin 디렉토리가 포함되어 있지 않은 환경 감지
if ! grep -q sbin <<< "$PATH"; then
        echo '$PATH에 sbin이 포함되어 있지 않습니다. "su" 대신에 "su -"을 사용해보세요.'
        exit
fi

if [[ "$EUID" -ne 0 ]]; then
        echo "이 설치 프로그램은 슈퍼유저 권한으로 실행해야 합니다."
        exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
        echo "시스템에는 TUN 장치가 없습니다.
이 설치 프로그램을 실행하기 전에 TUN을 활성화해야 합니다."
        exit
fi

new_client () {
        # 사용자 정의 client.ovpn 생성
        {
        cat /etc/openvpn/server/client-common.txt
        echo "<ca>"
        cat /etc/openvpn/server/easy-rsa/pki/ca.crt
        echo "</ca>"
        echo "<cert>"
        sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
        echo "</cert>"
        echo "<key>"
        cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
        echo "</key>"
        echo "<tls-crypt>"
        sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
        echo "</tls-crypt>"
        } > ~/"$client".ovpn
}

if [[ ! -e /etc/openvpn/server/server.conf ]]; then
        # wget 또는 curl이 설치되어 있지 않은 Debian minimal 설정 감지
        if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
                echo "이 설치 프로그램을 사용하려면 Wget이 필요합니다."
                read -n1 -r -p "아무 키나 눌러 Wget을 설치하고 계속 진행하세요..."
                apt-get update
                apt-get install -y wget
        fi
        clear
	echo 'OpenVPN'
        echo '안녕하세요. (roadwarrior) - .ovpn 발급 프로그램에 오신 것을 환영합니다!'
        # 시스템이 단일 IPv4를 가지고 있다면 자동으로 선택됩니다. 그렇지 않으면 사용자에게 물어봅니다.
        if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
                ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
        else
                number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
                echo
                echo "어떤 IPv4 주소를 사용하시겠습니까?"
                ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
                read -p "IPv4 주소 [1]: " ip_number
                until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
                        echo "$ip_number: 잘못된 선택입니다."
                        read -p "IPv4 주소 [1]: " ip_number
                done
                [[ -z "$ip_number" ]] && ip_number="1"
                ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
        fi
        # $ip이 사설 IP 주소이면 해당 서버는 프라이빗 네트워크에 위치하고 있어야 합니다.
        if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
                echo
                echo "이 서버는 NAT를 통해 연결되어 있습니다. 공용 IPv4 주소 또는 호스트 이름이 무엇인가요?"
                # 공용 IP 가져오기 및 grep로 정리
                get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
                read -p "공용 IPv4 주소 / 호스트 이름 [$get_public_ip]: " public_ip
                # checkip 서비스를 사용할 수 없거나 사용자가 입력하지 않았고 사용자가 제공한 경우 다시 물어봅니다.
                until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
                        echo "잘못된 입력입니다."
                        read -p "공용 IPv4 주소 / 호스트 이름: " public_ip
                done
                [[ -z "$public_ip" ]] && public_ip="$get_public_ip"
        fi
        # 시스템이 단일 IPv6를 가지고 있다면 자동으로 선택됩니다.
        if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
                ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
        fi
        # 시스템이 여러 개의 IPv6를 가지고 있다면 사용자에게 선택하도록 요청합니다.
        if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
                number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
                echo
                echo "어떤 IPv6 주소를 사용하시겠습니까?"
                ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
                read -p "IPv6 주소 [1]: " ip6_number
                until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
                        echo "$ip6_number: 잘못된 선택입니다."
                        read -p "IPv6 주소 [1]: " ip6_number
                done
                [[ -z "$ip6_number" ]] && ip6_number="1"
                ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
        fi
        echo
        echo "OpenVPN이 어떤 프로토콜을 사용하길 원하시나요?"
        echo "   1) UDP (권장)"
        echo "   2) TCP"
        read -p "프로토콜 [1]: " protocol
        until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
                echo "$protocol: 잘못된 선택입니다."
                read -p "프로토콜 [1]: " protocol
        done
        case "$protocol" in
                1|"")
                protocol=udp
                ;;
                2)
                protocol=tcp
                ;;
        esac
        echo
        echo "OpenVPN 포트 설정"
        read -p "포트 [1194]: " port
        until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
                echo "$port: 잘못된 포트입니다."
                read -p "포트 [1194]: " port
        done
        [[ -z "$port" ]] && port="1194"
        echo
        echo "클라이언트를 위한 DNS 서버를 선택하세요:"
        echo "   1) 현재 시스템 리졸버"
        echo "   2) Google"
        echo "   3) 1.1.1.1"
        echo "   4) OpenDNS"
        echo "   5) Quad9"
        echo "   6) AdGuard"
        read -p "DNS 서버 [1]: " dns
        until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
                echo "$dns: 잘못된 선택입니다."
                read -p "DNS 서버 [1]: " dns
        done
        echo

		# 첫 번째 클라이언트의 이름 입력 받기
		read -p "Name [client]: " unsanitized_client

		# 충돌을 피하기 위해 일부 문자만 허용
		client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")

		# 이름이 비어있으면 기본값으로 설정
		[[ -z "$client" ]] && client="client"

		echo

		# OpenVPN 설치 준비 완료 메시지 출력

		# 방화벽이나 iptables이 설치되어 있지 않은 경우 방화벽을 설치할 지 물어보고 설치
		if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
			if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
				firewall="firewalld"
				# 사용자에게 설치 여부를 알림
				# 계속 진행하면 방화벽이 설치되고 설정됨
				echo "firewalld, which is required to manage routing tables, will also be installed."
			elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
				# iptables은 firewalld보다 침투력이 낮기 때문에 알림을 표시하지 않음
				firewall="iptables"
			fi
		fi

		# 사용자 입력 대기
		read -n1 -r -p "Press any key to continue..."

		# 컨테이너에서 실행 중인 경우 충돌을 방지하기 위해 LimitNPROC 비활성화
		if systemd-detect-virt -cq; then
			mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
			echo "[Service]
		LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
		fi

		# OS에 따라 OpenVPN 및 관련 패키지 설치
		if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
			apt-get update
			apt-get install -y openvpn openssl ca-certificates $firewall
		elif [[ "$os" = "centos" ]]; then
			yum install -y epel-release
			yum install -y openvpn openssl ca-certificates tar $firewall
		else
			# Fedora의 경우
			dnf install -y openvpn openssl ca-certificates tar $firewall
		fi

		# 방화벽이 방금 설치되었다면 활성화
		if [[ "$firewall" == "firewalld" ]]; then
			systemctl enable --now firewalld.service
		fi

		# easy-rsa 다운로드
		easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.0/EasyRSA-3.1.0.tgz'
		mkdir -p /etc/openvpn/server/easy-rsa/
		{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
		chown -R root:root /etc/openvpn/server/easy-rsa/

		# easy-rsa 디렉토리로 이동
		cd /etc/openvpn/server/easy-rsa/

		# PKI 생성, CA 설정, 서버 및 클라이언트 인증서 생성
		./easyrsa init-pki
		./easyrsa --batch build-ca nopass
		EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
		EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

		# 필요한 파일들을 복사
		cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server

		# CRL은 각 클라이언트 연결시 읽히며, OpenVPN은 nobody로 실행됨
		chown nobody:"$group_name" /etc/openvpn/server/crl.pem

		# 디렉토리에 +x가 없으면 OpenVPN은 CRL 파일에 대한 stat()을 실행할 수 없음
		chmod o+x /etc/openvpn/server/

		# tls-crypt를 위한 키 생성
		openvpn --genkey --secret /etc/openvpn/server/tc.key

		# 미리 정의된 ffdhe2048 그룹을 사용하여 DH 파라미터 파일 생성
		echo '-----BEGIN DH PARAMETERS-----
		MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
		+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
		87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
		YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
		7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
		ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
		-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem

		# server.conf 파일 생성
		echo "local $ip
		port $port
		proto $protocol
		dev tun
		ca ca.crt
		cert server.crt
		key server.key
		dh dh.pem
		auth SHA512
		tls-crypt tc.key
		topology subnet
		server 10.8.0.0 255.255.255.0" > /etc/openvpn/server/server.conf

		# IPv6
		if [[ -z "$ip6" ]]; then
			echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
		else
			echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
			echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
		fi

		echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf

		# DNS 설정
		case "$dns" in
			1|"")
				# 적절한 resolv.conf를 찾음
				# systemd-resolved를 실행 중인 시스템에 필요
				if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
					resolv_conf="/etc/resolv.conf"
				else
					resolv_conf="/run/systemd/resolve/resolv.conf"
				fi
				# resolv.conf에서 리졸버 가져와 OpenVPN에 사용
				grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
					echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
				done
			;;
			2)
				echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
				echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
			;;
			3)
				echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
				echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
			;;
			4)
				echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
				echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
			;;
			5)
				echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
				echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
			;;
			6)
				echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
				echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
			;;
		esac

		echo 'push "block-outside-dns"' >> /etc/openvpn/server/server.conf
		# keepalive 설정: OpenVPN 연결이 끊어지면 10초마다 120초 동안 재시도
		echo "keepalive 10 120" >> /etc/openvpn/server/server.conf

		# 사용자 및 그룹 설정
		echo "user nobody
		group $group_name" >> /etc/openvpn/server/server.conf

		# 키와 터널을 지속적으로 유지
		echo "persist-key
		persist-tun" >> /etc/openvpn/server/server.conf

		# 로그 상세도 설정 (verbosity level 3)
		echo "verb 3" >> /etc/openvpn/server/server.conf

		# 인증서 폐기 리스트 (CRL) 검증
		echo "crl-verify crl.pem" >> /etc/openvpn/server/server.conf

		# UDP 프로토콜인 경우 explicit-exit-notify 옵션 추가
		if [[ "$protocol" = "udp" ]]; then
			echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
		fi

		# 시스템에서 net.ipv4.ip_forward 활성화
		echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf

		# 재부팅이나 서비스 다시 시작 없이 즉시 활성화
		echo 1 > /proc/sys/net/ipv4/ip_forward

		# IPv6 활성화 시
		if [[ -n "$ip6" ]]; then
			# 시스템에서 net.ipv6.conf.all.forwarding 활성화
			echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-openvpn-forward.conf
			# 재부팅이나 서비스 다시 시작 없이 즉시 활성화
			echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
		fi
# firewalld 서비스가 실행 중이면 방화벽 설정
if systemctl is-active --quiet firewalld.service; then
    # firewalld를 사용하여 방화벽 규칙 추가
    firewall-cmd --add-port="$port"/"$protocol"
    firewall-cmd --zone=trusted --add-source=10.8.0.0/24
    firewall-cmd --permanent --add-port="$port"/"$protocol"
    firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24

    # VPN 서브넷에 대한 NAT 설정
    firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
    firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"

    # IPv6 설정이 있는 경우
    if [[ -n "$ip6" ]]; then
        firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
        firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64

        # VPN 서브넷에 대한 IPv6 NAT 설정
        firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
        firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
    fi
else
    # firewalld가 실행 중이 아니면 iptables를 사용하여 방화벽 설정
    iptables_path=$(command -v iptables)
    ip6tables_path=$(command -v ip6tables)

    # OVZ 커널에서 nf_tables를 사용하는 경우 iptables-legacy를 사용
    if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
        iptables_path=$(command -v iptables-legacy)
        ip6tables_path=$(command -v ip6tables-legacy)
    fi

    # iptables 서비스 설정 파일 생성
    echo "[Unit]
	Before=network.target
	[Service]
	Type=oneshot
	ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
	ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
	ExecStart=$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
	ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
	ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
	ExecStop=$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
	ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service

		# IPv6 설정이 있는 경우 iptables 설정 파일에 추가
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
	ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
	ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
	ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
	ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
		fi

		# 서비스가 종료될 때 남아 있도록 RemainAfterExit 옵션 추가
		echo "RemainAfterExit=yes
	[Install]
	WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service

		# iptables 서비스 활성화
		systemctl enable --now openvpn-iptables.service
	fi

	# SELinux이 활성화되어 있고 사용자가 사용자 지정 포트를 선택한 경우 설정이 필요함
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# semanage가 설치되어 있지 않은 경우 설치
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				# CentOS 7
				yum install -y policycoreutils-python
			else
				# CentOS 8 또는 Fedora
				dnf install -y policycoreutils-python-utils
			fi
		fi
		# SELinux 설정 추가
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi

	# 서버가 NAT 뒤에 있는 경우 올바른 IP 주소 사용
	[[ -n "$public_ip" ]] && ip="$public_ip"

	# 클라이언트 공통 설정 파일 생성
	echo "client
	dev tun
	proto $protocol
	remote $ip $port
	resolv-retry infinite
	nobind
	persist-key
	persist-tun
	remote-cert-tls server
	auth SHA512
	ignore-unknown-option block-outside-dns
	verb 3" > /etc/openvpn/server/client-common.txt

	# OpenVPN 서비스 활성화 및 시작
	systemctl enable --now openvpn-server@server.service

	# 사용자 정의 클라이언트 설정 파일(client.ovpn) 생성
	new_client

	echo
	echo "완료!"
	echo
	echo "클라이언트 구성은 다음 위치에 있습니다. :" ~/"$client.ovpn"
	echo "새로운 클라이언트를 추가하려면 이 스크립트를 다시 실행하십시오."
	else
	clear
	echo "OpenVPN이 이미 설치되어있습니다."
	echo
	echo "옵션을 선택하십시오"
	echo "   1. 새 클라이언트 추가"
	echo "   2. 기존 클라이언트 취소"
	echo "   3. OpenVPN 제거"
	echo "   4. 종료"
	read -p "옵션 : " option
	until [[ "$option" =~ ^[1-4]$ ]]; do
		echo "$option: invalid selection."
		read -p "Option: " option
	done
	case "$option" in
		1)
			echo
			echo "클라이언트에 대한 이름을 제공하세요:"
			read -p "이름: " unsanitized_client
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
				echo "$client: 잘못된 이름입니다."
				read -p "이름: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			done
			cd /etc/openvpn/server/easy-rsa/
			./easyrsa --batch --days=3650 build-client-full "$client" nopass
			# 사용자 정의 클라이언트.ovpn 생성
			new_client
			echo
			echo "$client 추가됨. 구성은 다음 위치에 있습니다:" ~/"$client.ovpn"
			exit
		;;
		2)
			# 이 옵션은 조금 더 자세하게 문서화되어도 좋고 아마 간소화되어도 좋을 것입니다.
			number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "기존 클라이언트가 없습니다!"
				exit
			fi
			echo
			echo "취소할 클라이언트 선택:"
			tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			read -p "클라이언트: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: 잘못된 선택입니다."
				read -p "클라이언트: " client_number
			done
			client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			echo
			read -p "$client 취소를 확인하시겠습니까? [y/N]: " revoke
			until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
				echo "$revoke: 잘못된 선택입니다."
				read -p "$client 취소를 확인하시겠습니까? [y/N]: " revoke
			done
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				cd /etc/openvpn/server/easy-rsa/
				./easyrsa --batch revoke "$client"
				./easyrsa --batch --days=3650 gen-crl
				rm -f /etc/openvpn/server/crl.pem
				cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
				# CRL은 OpenVPN이 nobody로 드롭될 때마다 각 클라이언트 연결시에 읽힙니다.
				chown nobody:"$group_name" /etc/openvpn/server/crl.pem
				echo
				echo "$client 취소됨!"
			else
				echo
				echo "$client 취소가 중단되었습니다!"
			fi
			exit
		;;
		3)
			echo
			read -p "OpenVPN 제거를 확인하시겠습니까? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: 잘못된 선택입니다."
				read -p "OpenVPN 제거를 확인하시겠습니까? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
					# Firewalld 리로드를 피하기 위해 영구 및 비영구 규칙 모두 사용
					firewall-cmd --remove-port="$port"/"$protocol"
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --remove-port="$port"/"$protocol"
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now openvpn-iptables.service
					rm -f /etc/systemd/system/openvpn-iptables.service
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
					semanage port -d -t openvpn_port_t -p "$protocol" "$port"
				fi
				systemctl disable --now openvpn-server@server.service
				rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
				rm -f /etc/sysctl.d/99-openvpn-forward.conf
				if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
					rm -rf /etc/openvpn/server
					apt-get remove --purge -y openvpn
				else
					# 그렇지 않으면 OS는 CentOS 또는 Fedora여야 합니다
					yum remove -y openvpn
					rm -rf /etc/openvpn/server
				fi
				echo
				echo "OpenVPN이 제거되었습니다!"
			else
				echo
				echo "OpenVPN 제거가 중단되었습니다!"
			fi
			exit
		;;
		4)
			exit
		;;
	esac
fi
