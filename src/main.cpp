#include <iostream>
#include <pcap.h>
using namespace std;

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];  // Buffer para mensajes de error de npcap
    pcap_if_t* interfaces;          // Lista de interfaces que npcap encuentra

    // Pedirle a npcap que encuentre todas las interfaces de red
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        cerr << "Error buscando interfaces: " << errbuf << endl;
        return 1;
    }

    // Recorrer e imprimir cada interfaz encontrada
    cout << "Interfaces de red disponibles:\n";

    int numero = 1;
    pcap_if_t* iface;

    for (iface = interfaces; iface != nullptr; iface = iface->next) {
        cout << numero << ". " << iface->name << "\n";
        if (iface->description) {
            cout << "   Descripcion: " << iface->description << "\n";
        }
        numero++;
    }

    if (numero == 1) {
        cout << "No se encontraron interfaces\n";
        cout << "Verificar que npcap este instalado ";
    }

    system("pause");
    // Liberar la memoria que npcap reservo para la lista
    pcap_freealldevs(interfaces);

    return 0;
}