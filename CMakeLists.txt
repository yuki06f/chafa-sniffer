cmake_minimum_required(VERSION 3.20)
project(ChafaSniffer VERSION 1.0 LANGUAGES CXX)

# Usar C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Rutas del npcap SDK
set(NPCAP_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/libs/npcap/Include")
set(NPCAP_LIB_DIR     "${CMAKE_SOURCE_DIR}/libs/npcap/Lib/x64")

# Archivos fuente (por ahora solo main)
add_executable(chafa-sniffer
    src/main.cpp
)

# Incluir headers de npcap
target_include_directories(chafa-sniffer PRIVATE
    ${NPCAP_INCLUDE_DIR}
)

# Enlazar con las librerías de npcap
target_link_libraries(chafa-sniffer PRIVATE
    ${NPCAP_LIB_DIR}/wpcap.lib
    ${NPCAP_LIB_DIR}/Packet.lib
)