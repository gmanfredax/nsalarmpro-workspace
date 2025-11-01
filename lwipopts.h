#ifndef LWIPOPTS_H
#define LWIPOPTS_H

#define MEM_SIZE                   (48*1024)
#define PBUF_POOL_SIZE             16
#define PBUF_POOL_BUFSIZE          1536
#define MEMP_NUM_TCP_PCB           8
#define TCP_MSS                    1460
#define TCP_WND                    (8*TCP_MSS)
#define TCP_SND_BUF                (4*TCP_MSS)
#define LWIP_DHCP                  1
#define LWIP_NETIF_LINK_CALLBACK   1
#define LWIP_HTTPD_CGI             1
#define LWIP_HTTPD_SSI             1
#define LWIP_TCPIP_CORE_LOCKING    1
#define LWIP_SO_RCVTIMEO           1
#define LWIP_SOCKET                0
#define LWIP_SNTP                  1
#define SNTP_SERVER_DNS            1
#define SNTP_MAX_SERVERS           1

#endif
