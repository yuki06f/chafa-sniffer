# ChafaSniffer

Packet sniffer desarrollado en **C++17** con captura de tráfico vía **Npcap** e interfaz gráfica en **Qt6**, inspirado funcionalmente en Wireshark.

Proyecto desarrollado para la materia de **Redes de Computadoras I** — Universidad Autónoma de Aguascalientes.

---

## Descripción

ChafaSniffer permite capturar tráfico de red en tiempo real, interpretar la estructura interna de cada paquete (Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP), visualizarlo en una interfaz con tres áreas inspiradas en Wireshark, aplicar filtros sobre el tráfico capturado, y exportar los resultados a un archivo de hoja de cálculo.

## Características principales

- Captura de tráfico en tiempo real en modo promiscuo, sobre cualquier interfaz disponible (física o virtual)
- Control completo del ciclo de vida de la captura: Iniciar, Pausar, Reanudar, Reiniciar y Detener
- Parser de protocolos por capas: Ethernet, ARP, IPv4, IPv6, TCP, UDP e ICMP
- Identificación automática de servicios de aplicación por número de puerto (HTTP, HTTPS, DNS, SSH, FTP, entre otros)
- Interfaz gráfica de tres áreas:
  - **Área 1** — tabla de tráfico capturado en tiempo real, con codificación por colores según protocolo
  - **Área 2** — árbol de detalle estructurado del paquete seleccionado
  - **Área 3** — volcado hexadecimal + ASCII del contenido crudo del paquete
- Filtrado por IP origen, IP destino, puerto origen, puerto destino y protocolo
- Filtros rápidos de un clic para TCP, UDP, ICMP, ARP, HTTP, HTTPS y DNS
- Exportación de resultados (totales o filtrados) a formato compatible con Excel

## Requisitos

### Para ejecutar el programa (usuario final)

- Windows 10 / 11 de 64 bits
- **Driver de Npcap instalado** — necesario para la captura, independientemente de cómo se distribuya el programa.
  Descárgalo desde [npcap.com](https://npcap.com/) e instálalo activando la opción **"Install Npcap in WinPcap API-compatible mode"**.
  No es obligatorio, el paquete instalador se encargará de verificar la existencia de esta librería
---

## Instalación y ejecución (paquete ya compilado)

1. Instala el driver de Npcap (ver sección de requisitos arriba) — **este paso es obligatorio incluso usando el ejecutable ya compilado**, ya que el driver vive a nivel de sistema operativo y no se distribuye dentro del programa.
2. Descarga la carpeta del paquete ejecutable desde la sección de [Releases](../../releases) de este repositorio (o desde donde tu equipo la esté compartiendo).
3. Descomprime la carpeta completa en cualquier ubicación de tu equipo. **No muevas el `.exe` fuera de su carpeta** — las DLLs de Qt y de Npcap que lo acompañan deben permanecer junto a él.
4. Ejecuta `chafa-sniffer.exe` haciendo doble clic.
5. En la ventana inicial, selecciona la interfaz de red sobre la cual deseas capturar y pulsa **Iniciar**.

 Si Windows muestra una advertencia de SmartScreen al ejecutar el `.exe` (por no estar firmado digitalmente), selecciona **"Más información" → "Ejecutar de todas formas"**.

---

## Estructura del proyecto

```
chafa-sniffer/
├── src/
│   ├── capture/      motor de captura con Npcap
│   ├── parser/       interpretación de protocolos
│   ├── filters/      motor de filtros
│   ├── export/       xportación de resultados a Excel
│   └── gui/          interfaz gráfica (Qt6)
├── libs/
│   └── npcap/         libreria
├── docs/              manual de usuario y reporte técnico
├── CMakeLists.txt
└── README.md
```
