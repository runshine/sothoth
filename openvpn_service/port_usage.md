# VPN_SERVER_IP:  xxx.xxx.0.2
## PORT_MAPPING

EIP -->  VPN --> SERVICE_NAME
1. 8080-->file_service
2. 8848-->nacos_service
3. 11194/udp--> VPN_SERVER_CLUSTER_01
4. 11195/udp--> VPN_SERVER_CLUSTER_01
5. 11196/udp--> VPN_SERVER_CLUSTER_01
6. 11197/udp--> VPN_SERVER_CLUSTER_01


# client port usage
11188 --> rpcapd
11189 --> frida_server
11190 --> nacos_client
11191 --> dockerd remote control api
11192 --> sshd
11194 --> nginx openvpn proxy
11195 --> nginx openvpn proxy
11196 --> nginx openvpn proxy
11197 --> nginx openvpn proxy
11198 --> ttyd
11199 --> nginx VPN_SERVER tcp port proxy