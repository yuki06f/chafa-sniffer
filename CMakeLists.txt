cmake_minimum_required(VERSION 3.20)
project(ChafaSniffer VERSION 1.0 LANGUAGES CXX)

# Qt
find_package(Qt6 REQUIRED COMPONENTS Widgets)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

#excel

# Rutas de Npcap
set(NPCAP_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/libs/npcap/Include")
set(NPCAP_LIB_DIR     "${CMAKE_SOURCE_DIR}/libs/npcap/Lib/x64")

# Ejecutable
# Archivos fuente 
add_executable(chafa-sniffer
    src/main.cpp

    src/gui/mainwindow.h
    src/gui/mainwindow.ui

    src/filters/filter_engine.h
    src/filters/filters.h
    src/gui/mainwindow.cpp
    src/export/exportador.cpp
    src/export/exportador.h
)

# Includes
target_include_directories(chafa-sniffer PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${NPCAP_INCLUDE_DIR}
)

# Librerías
target_link_libraries(chafa-sniffer PRIVATE
    Qt6::Widgets
    "${NPCAP_LIB_DIR}/wpcap.lib"
    "${NPCAP_LIB_DIR}/Packet.lib"
    ws2_32
)