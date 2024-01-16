# OpenVPN Install Shell Script

본 스크립트는 클라이언트에게 본인이 사용하고 있는 VM 인스턴스를 원격으로 접속할 수 있게 할 수 있도록 .ovpn을 발급해주는 스크립트입니다.

OpenVPN을 설치하려면 제공된 셸 스크립트를 사용하여 터미널에서 다음 명령을 실행할 수 있습니다.

```bash
sudo wget https://raw.githubusercontent.com/Azabell1993/openVPN/main/openvpn_install.sh -O openvpn_install.sh && sudo bash openvpn_install.sh
```

## 1. 처음 설치할때 스크립트 실행시
``` bash
이 OpenVPN 로드 워리어 설치 프로그램에 오신 것을 환영합니다!

이 서버는 NAT를 통해 연결되어 있습니다. 공용 IPv4 주소 또는 호스트 이름이 무엇인가요?
공용 IPv4 주소 / 호스트 이름 [61.109.238.202]:

OpenVPN이 어떤 프로토콜을 사용하길 원하시나요?
   1) UDP (권장)
   2) TCP
프로토콜 [1]: 1

OpenVPN 포트 설정
포트 [1194]:

클라이언트를 위한 DNS 서버를 선택하세요:
   1) 현재 시스템 리졸버
   2) Google
   3) 1.1.1.1
   4) OpenDNS
   5) Quad9
   6) AdGuard
DNS 서버 [1]: 2

Name [client]:

Press any key to continue...
```

- 서버의 공용 IPv4 주소 또는 호스트 이름 입력:
스크립트 실행 후, 서버의 공용 IPv4 주소나 호스트 이름을 묻는 메시지가 나타납니다.
사용자는 해당 정보를 입력하고 엔터 키를 누릅니다.

- OpenVPN 프로토콜 선택:
프로토콜 선택 메시지가 나타나면,
1을 선택하여 UDP 프로토콜을 사용하도록 선택하고 엔터 키를 누릅니다.

- OpenVPN 포트 설정:
포트 설정 메시지가 나타나면, 기본값으로 엔터 키를 눌러 1194 포트를 사용하도록 설정합니다.

- 클라이언트 DNS 서버 선택:
DNS 서버 선택 메시지가 나타나면, 기본값으로 엔터 키를 눌러 현재 시스템 리졸버(옵션 1)를 선택합니다.

- 클라이언트 이름 입력:
이름 입력 메시지가 나타나면, 기본값으로 엔터 키를 눌러 "client"로 설정합니다.

- 작업 완료 및 클라이언트 구성 위치 확인:
스크립트가 실행을 완료하면 클라이언트 구성 파일 위치에 대한 메시지가 나타납니다.
/root/client.ovpn에 새로운 클라이언트 구성이 생성되었습니다.

#### 완료 후 메세지
```  
완료!

클라이언트 구성은 다음 위치에 있습니다. : /root/client.ovpn
새로운 클라이언트를 추가하려면 이 스크립트를 다시 실행하십시오.
```  
## 2. 설치한 후 다시 스크립트 실행시 
```  
OpenVPN이 이미 설치되어있습니다.

옵션을 선택하십시오
   1. 새 클라이언트 추가
   2. 기존 클라이언트 취소
   3. OpenVPN 제거
   4. 종료
옵션 :
```  
