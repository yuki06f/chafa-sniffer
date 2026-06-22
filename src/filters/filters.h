#pragma once
#include "../packet_info.h"
#include <string>
#include <algorithm>

using namespace std;

// Estructura para almacenar los filtros que el usuario digite
struct FilterCriteria {
    string ip_org = "";        
    string ip_dst = "";        
    uint16_t puerto_org = 0;   
    uint16_t puerto_dst = 0;   
    string protocolo = "";     // "TCP", "UDP", "ICMP"
};

class FilterEngine {
public:
    // Retorna true si el paquete cumple con TODOS los filtros activos
    static bool cumpleFiltros(const PacketInfo& pkt, const FilterCriteria& criterio) {
        
        // Filtro IP Origen (si no está vacío y no coincide, se descarta)
        if (!criterio.ip_org.empty() && pkt.ip_org != criterio.ip_org) {
            return false; 
        }

        // Filtro IP Destino
        if (!criterio.ip_dst.empty() && pkt.ip_dst != criterio.ip_dst) {
            return false;
        }

        // Filtro Puerto Origen (si es diferente de 0 y no coincide, se descarta)
        if (criterio.puerto_org != 0 && pkt.puerto_org != criterio.puerto_org) {
            return false;
        }

        // Filtro Puerto Destino
        if (criterio.puerto_dst != 0 && pkt.puerto_dst != criterio.puerto_dst) {
            return false;
        }

        // Filtro Protocolo (compara en mayúsculas para evitar errores)
        if (!criterio.protocolo.empty()) {
            string proto_pkt = pkt.protocolo;
            string proto_crit = criterio.protocolo;
            
            transform(proto_pkt.begin(), proto_pkt.end(), proto_pkt.begin(), ::toupper);
            transform(proto_crit.begin(), proto_crit.end(), proto_crit.begin(), ::toupper);
            
            if (proto_pkt != proto_crit) {
                return false;
            }
        }

        // Si no se descartó en ninguna condición, el paquete pasa el filtro
        return true;
    }
};