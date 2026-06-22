#pragma once
#include <string>
#include <vector>
#include <cstdint>

using namespace std;

// representa a un paquete y se usa en
// capture/   llenar con ncap
// parser/    extrae los campos de los bytes crudos
// filters/   evaluar para saber si pasa el filtro
// export/    para csv
// gui/       lo muestra en pantalla
struct PacketInfo {
    int numero;                 // número de paquete 
    string tiempo;          // hora de captura como string hh:mm:ss:ms
    int longitud;              // longitud real del paquete en bytes

    // Ethernet
    string mac_org;       // MAC origen  
    string mac_dst;       // MAC destino 
    uint16_t ethertype = 0; // 0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6

    // IP
    string ip_org;        // IP origen 
    string ip_dst;        // IP destino 
    uint8_t ttl = 0;       // tiempo vida
    uint8_t protocolo_num = 0; // 6=TCP, 17=UDP, 1=ICMP

    // Protocolo nombre
    string protocolo;     

    // tcp y udp puertos
    uint16_t puerto_org = 0;
    uint16_t puerto_dst = 0;

    // Contenido crudo sin manejar
    vector<uint8_t> bytes;
    string info_resumen;
};