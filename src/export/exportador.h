#pragma once
#include <vector>
#include "packet_info.h" //

// Declaramos la función para que otros archivos (como tu MainWindow) sepan que existe
void exportarAExcelMultiplataforma(const std::vector<PacketInfo>& listaPaquetes); //