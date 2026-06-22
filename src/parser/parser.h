#pragma once
#include "../packet_info.h"
#include <string>
#include <vector>
#include <pcap.h>
#include <cstdint>
#include <winsock2.h>

using namespace std;

#pragma pack(push, 1)

struct ip_header{
    uint8_t version_ihl;
    uint8_t tipo_servicio;
    uint16_t longitud_total;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t chk_sum;
    uint32_t ip_org;
    uint32_t ip_dst;
};

struct ipv6_header{
    uint32_t version_tc_flow;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t ip_org[16];
    uint8_t ip_dst[16];
};

struct ethernet_header{
    uint8_t mac_dst[6];
    uint8_t mac_org[6];
    uint16_t protocol;
};

struct tcp_header{
    uint16_t puerto_org;
    uint16_t puerto_dst;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t chk_sum;
    uint16_t urgent;
};

#pragma pack(pop)

class Parser
{
public:

    static void parsear(const u_char* crudo,
                        int longitud,
                        PacketInfo& info)
    {
        if (longitud < 14)
            return;

        // Info por defecto para cualquier paquete no reconocido
        info.info_resumen = "Len=" + to_string(longitud);

        const ethernet_header* eth =
            reinterpret_cast<const ethernet_header*>(crudo);

        info.mac_org = mac_string(eth->mac_org);
        info.mac_dst = mac_string(eth->mac_dst);

        uint16_t ethertype = ntohs(eth->protocol);
        info.ethertype = ethertype;

        // Detectar protocolos Ethernet
        if (ethertype == 0x0806)
        {
            info.protocolo = "ARP";
            return;
        }

        if (ethertype == 0x86DD)
        {
            if(longitud < 54)
                return;

            const ipv6_header* ip6 =
                reinterpret_cast<const ipv6_header*>(crudo + 14);

            info.ip_org = ipv6_string(ip6->ip_org);
            info.ip_dst = ipv6_string(ip6->ip_dst);

            if(ip6->next_header == 6) // TCP
            {
                const tcp_header* tcp =
                    reinterpret_cast<const tcp_header*>(crudo + 14 + 40);

                info.puerto_org = ntohs(tcp->puerto_org);
                info.puerto_dst = ntohs(tcp->puerto_dst);

                string servicio = detectarServicio(info.puerto_dst);
                if(servicio.empty()) servicio = detectarServicio(info.puerto_org);

                if(!servicio.empty()) info.protocolo = servicio;
                else info.protocolo = "TCP IPv6";

                // Extraccion de banderas TCP
                string banderas = extraerBanderasTCP(tcp->flags);
                info.info_resumen = to_string(info.puerto_org) + " -> " + to_string(info.puerto_dst);
                if(!banderas.empty()) info.info_resumen += " [" + banderas + "]";
                info.info_resumen += " Len=" + to_string(longitud);
            }

            else if(ip6->next_header == 17) // UDP
            {
                const uint8_t* udp = crudo + 14 + 40;

                info.puerto_org = ntohs(*reinterpret_cast<const uint16_t*>(udp));
                info.puerto_dst = ntohs(*reinterpret_cast<const uint16_t*>(udp + 2));

                string servicio = detectarServicio(info.puerto_dst);
                if(servicio.empty()) servicio = detectarServicio(info.puerto_org);

                if(!servicio.empty()) info.protocolo = servicio;
                else info.protocolo = "UDP IPv6";

                // Resumen para UDP
                info.info_resumen = to_string(info.puerto_org) + " -> " + to_string(info.puerto_dst) + " Len=" + to_string(longitud);
            }
            else
            {
                info.protocolo = "IPv6";
            }

            return;
        }

        if (ethertype != 0x0800)
        {
            info.protocolo = "Otro";
            return;
        }

        if (longitud < 34)
            return;

        const ip_header* ip =
            reinterpret_cast<const ip_header*>(crudo + 14);

        info.ip_org = ip_string(ip->ip_org);
        info.ip_dst = ip_string(ip->ip_dst);
        info.ttl = ip->ttl;
        info.protocolo_num = ip->protocol;

        int ip_header_len = (ip->version_ihl & 0x0F) * 4;

        // TCP
        if (ip->protocol == 6)
        {
            if (longitud < 14 + ip_header_len + 20)
                return;

            const tcp_header* tcp =
                reinterpret_cast<const tcp_header*>(crudo + 14 + ip_header_len);

            info.puerto_org = ntohs(tcp->puerto_org);
            info.puerto_dst = ntohs(tcp->puerto_dst);

            string servicio = detectarServicio(info.puerto_dst);
            if(servicio.empty()) servicio = detectarServicio(info.puerto_org);

            if(!servicio.empty()) info.protocolo = servicio;
            else info.protocolo = "TCP";

            // Extraccion de banderas TCP
            string banderas = extraerBanderasTCP(tcp->flags);
            info.info_resumen = to_string(info.puerto_org) + " -> " + to_string(info.puerto_dst);
            if(!banderas.empty()) info.info_resumen += " [" + banderas + "]";
            info.info_resumen += " Len=" + to_string(longitud);
        }

        // UDP
        else if (ip->protocol == 17)
        {
            if (longitud < 14 + ip_header_len + 8)
                return;

            const uint8_t* udp = crudo + 14 + ip_header_len;

            info.puerto_org = ntohs(*reinterpret_cast<const uint16_t*>(udp));
            info.puerto_dst = ntohs(*reinterpret_cast<const uint16_t*>(udp + 2));

            string servicio = detectarServicio(info.puerto_dst);
            if(servicio.empty()) servicio = detectarServicio(info.puerto_org);

            if(!servicio.empty()) info.protocolo = servicio;
            else info.protocolo = "UDP";

            // Resumen para UDP
            info.info_resumen = to_string(info.puerto_org) + " -> " + to_string(info.puerto_dst) + " Len=" + to_string(longitud);
        }

        // ICMP
        else if (ip->protocol == 1)
        {
            info.protocolo = "ICMP";
        }

        else
        {
            info.protocolo = "Otro";
        }
    }

private:


    static string extraerBanderasTCP(uint8_t flags)
    {
        string banderas = "";
        if (flags & 0x01) banderas += "FIN, ";
        if (flags & 0x02) banderas += "SYN, ";
        if (flags & 0x04) banderas += "RST, ";
        if (flags & 0x08) banderas += "PSH, ";
        if (flags & 0x10) banderas += "ACK, ";
        if (flags & 0x20) banderas += "URG, ";

        if (!banderas.empty()) {
            banderas = banderas.substr(0, banderas.length() - 2); // Remueve coma y espacio final
        }
        return banderas;
    }

    static string detectarServicio(uint16_t puerto)
    {
        switch(puerto)
        {
        case 20: return "FTP-DATA";
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "TELNET";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 67:
        case 68: return "DHCP";
        case 69: return "TFTP";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 123: return "NTP";
        case 143: return "IMAP";
        case 161: return "SNMP";
        case 179: return "BGP";
        case 389: return "LDAP";
        case 443: return "HTTPS";
        case 445: return "SMB";
        case 514: return "SYSLOG";
        case 587: return "SMTP Secure";
        case 636: return "LDAPS";
        case 993: return "IMAPS";

        default:
            return "";
        }
    }

    static string mac_string(const uint8_t* mac)
    {
        char buff[18];

        snprintf(buff,
                 sizeof(buff),
                 "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac[0], mac[1], mac[2],
                 mac[3], mac[4], mac[5]);

        return string(buff);
    }

    static string ip_string(uint32_t ip)
    {
        uint32_t ip_host = ntohl(ip);

        return to_string((ip_host >> 24) & 0xFF) + "." +
               to_string((ip_host >> 16) & 0xFF) + "." +
               to_string((ip_host >> 8) & 0xFF) + "." +
               to_string(ip_host & 0xFF);
    }

    static string ipv6_string(const uint8_t* ip)
    {
        char buffer[40];

        snprintf(buffer, sizeof(buffer),
                 "%x:%x:%x:%x:%x:%x:%x:%x",
                 (ip[0] << 8) | ip[1],
                 (ip[2] << 8) | ip[3],
                 (ip[4] << 8) | ip[5],
                 (ip[6] << 8) | ip[7],
                 (ip[8] << 8) | ip[9],
                 (ip[10] << 8) | ip[11],
                 (ip[12] << 8) | ip[13],
                 (ip[14] << 8) | ip[15]);

        return string(buffer);
    }
};