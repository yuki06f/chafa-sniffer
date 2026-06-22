#include "exportador.h"
#include <QFile>
#include <QTextStream>
#include <QFileDialog>
#include <QMessageBox>
#include <QStringList>
#include <QDir>

void exportarAExcelMultiplataforma(const std::vector<PacketInfo>& listaPaquetes) { //
    if (listaPaquetes.empty()) {
        QMessageBox::warning(nullptr, "Exportar", "No hay paquetes seleccionados para exportar.");
        return;
    }

    // 1. Solicitar ruta al usuario (Forzamos la extensión .xls)
    QString filePath = QFileDialog::getSaveFileName(
        nullptr, 
        "Guardar como Excel", 
        "paquetes_capturados.xls", 
        "Archivos de Excel (*.xls)"
    );

    if (filePath.isEmpty()) return;

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(nullptr, "Error", "No se pudo crear el archivo.");
        return;
    }

    QTextStream out(&file);
    //out.setCodec("UTF-8"); // Codificación correcta para cadenas strings de red

    // 2. Estructura base del libro XML de Excel
    out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    out << "<?mso-application progid=\"Excel.Sheet\"?>\n";
    out << "<Workbook xmlns=\"urn:schemas-microsoft-com:office:spreadsheet\"\n"
        << " xmlns:o=\"urn:schemas-microsoft-com:office:office\"\n"
        << " xmlns:x=\"urn:schemas-microsoft-com:office:excel\"\n"
        << " xmlns:ss=\"urn:schemas-microsoft-com:office:spreadsheet\"\n"
        << " xmlns:html=\"http://www.w3.org/TR/REC-html40\">\n";
    
    // Configuración de Estilos Visuales (Colores y Bordes)
    out << " <Styles>\n"
        << "  <Style ss:ID=\"Default\" ss:Name=\"Normal\">\n"
        << "   <Alignment ss:Vertical=\"Bottom\"/>\n"
        << "   <Borders/>\n"
        << "   <Font ss:FontName=\"Segoe UI\" x:Family=\"Swiss\" ss:Size=\"10\"/>\n"
        << "   <Interior/>\n"
        << "   <NumberFormat/>\n"
        << "   <Protection/>\n"
        << "  </Style>\n"
        << "  <Style ss:ID=\"Cabecera\">\n"
        << "   <Alignment ss:Horizontal=\"Center\" ss:Vertical=\"Center\"/>\n"
        << "   <Borders>\n"
        << "    <Border ss:Position=\"Bottom\" ss:LineStyle=\"Continuous\" ss:Weight=\"1\" ss:Color=\"#D9D9D9\"/>\n"
        << "   </Borders>\n"
        << "   <Font ss:FontName=\"Segoe UI\" x:Family=\"Swiss\" ss:Size=\"11\" ss:Color=\"#FFFFFF\" ss:Bold=\"1\"/>\n"
        << "   <Interior ss:Color=\"#1F4E78\" ss:Pattern=\"Solid\"/>\n"
        << "  </Style>\n"
        << "  <Style ss:ID=\"FilaZebra\">\n"
        << "   <Interior ss:Color=\"#F2F5F8\" ss:Pattern=\"Solid\"/>\n"
        << "   <Borders>\n"
        << "    <Border ss:Position=\"Bottom\" ss:LineStyle=\"Continuous\" ss:Weight=\"1\" ss:Color=\"#E0E0E0\"/>\n"
        << "   </Borders>\n"
        << "  </Style>\n"
        << "  <Style ss:ID=\"FilaNormal\">\n"
        << "   <Borders>\n"
        << "    <Border ss:Position=\"Bottom\" ss:LineStyle=\"Continuous\" ss:Weight=\"1\" ss:Color=\"#E0E0E0\"/>\n"
        << "   </Borders>\n"
        << "  </Style>\n"
        << " </Styles>\n";

    out << " <Worksheet ss:Name=\"Paquetes\">\n"
        << "  <Table>\n";

    // Asignar anchos predeterminados a las 13 columnas de datos
    int anchos[] = {50, 90, 80, 120, 120, 70, 110, 110, 50, 60, 70, 70, 70};
    for (int i = 0; i < 13; ++i) {
        out << "   <Column ss:Width=\"" << anchos[i] << "\"/>\n";
    }

    // 3. Escribir fila de cabeceras
    QStringList headers = {
        "No.", "Tiempo", "Longitud", "MAC Origen", "MAC Destino", 
        "EtherType", "IP Origen", "IP Destino", "TTL", "Protocolo Num", 
        "Protocolo", "Puerto Org", "Puerto Dst"
    };
    
    out << "   <Row ss:AutoFitHeight=\"0\" ss:Height=\"25\">\n";
    for (const QString& head : headers) {
        out << "    <Cell ss:StyleID=\"Cabecera\"><Data ss:Type=\"String\">" << head << "</Data></Cell>\n";
    }
    out << "   </Row>\n";

    // 4. Llenar filas dinámicamente con los datos capturados
    bool filaPar = false;
    for (const auto& pkt : listaPaquetes) { 
        QString estiloFila = filaPar ? " ss:StyleID=\"FilaZebra\"" : " ss:StyleID=\"FilaNormal\"";
        out << "   <Row ss:Height=\"18\">\n";
        out << "    <Cell" << estiloFila << "><Data ss:Type=\"Number\">" << pkt.numero << "</Data></Cell>\n"; 
        out << "    <Cell" << estiloFila << "><Data ss:Type=\"String\">" << QString::fromStdString(pkt.tiempo) << "</Data></Cell>\n"; 
        out << "    <Cell" << estiloFila << "><Data ss:Type=\"Number\">" << pkt.longitud << "</Data></Cell>\n"; 
        out << "    <Cell" << estiloFila << "><Data ss:Type=\"String\">" << QString::fromStdString(pkt.mac_org) << "</Data></Cell>\n"; 
        out << "    <Cell" << estiloFila << "><Data ss:Type=\"String\">" << QString::fromStdString(pkt.mac_dst) << "</Data></Cell>\n"; 
        
        QString ethHex = "0x" + QString::number(pkt.ethertype, 16).toUpper().rightJustified(4, '0'); 
        out << "    <Cell" << estiloFila << "><Data ss:Type=\"String\">" << ethHex << "</Data></Cell>\n";
        
        out << "    <Cell" << estiloFila << "><Data ss:Type=\"String\">" << QString::fromStdString(pkt.ip_org) << "</Data></Cell>\n"; 
        out << "    <Cell" << estiloFila << "><Data ss:Type=\"String\">" << QString::fromStdString(pkt.ip_dst) << "</Data></Cell>\n"; 
        out << "    <Cell" << estiloFila << "><Data ss:Type=\"Number\">" << pkt.ttl << "</Data></Cell>\n"; 
        out << "    <Cell" << estiloFila << "><Data ss:Type=\"Number\">" << pkt.protocolo_num << "</Data></Cell>\n"; 
        out << "    <Cell" << estiloFila << "><Data ss:Type=\"String\">" << QString::fromStdString(pkt.protocolo) << "</Data></Cell>\n"; 
        out << "    <Cell" << estiloFila << "><Data ss:Type=\"Number\">" << pkt.puerto_org << "</Data></Cell>\n"; 
        out << "    <Cell" << estiloFila << "><Data ss:Type=\"Number\">" << pkt.puerto_dst << "</Data></Cell>\n"; 
        out << "   </Row>\n";
        filaPar = !filaPar;
    }

    out << "  </Table>\n"
        << " </Worksheet>\n"
        << "</Workbook>\n";

    file.close();
    QMessageBox::information(nullptr, "Éxito", "Los paquetes se exportaron correctamente a:\n" + filePath);
}