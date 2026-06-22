#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "../filters/filter_engine.h"
#include <QMessageBox>
#include <QColor>
#include "../export/exportador.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , ultimoPaqueteMostrado(0)
{
    ui->setupUi(this);

    // Inicializacion del backend de captura
    captura = new Capture(&paquetes);

    // Poblar lista de interfaces de red al arrancar
    cargarInterfaces();

    connect(ui->interfaces, &QListWidget::itemDoubleClicked,
            this, &MainWindow::iniciarCapturaDesdeLista);

    // Conexiones del menu principal
    connect(ui->actionIniciar_Captura, &QAction::triggered, this, &MainWindow::accion_Iniciar_triggered);
    connect(ui->actionDetener, &QAction::triggered, this, &MainWindow::accion_Detener_triggered);
    connect(ui->actionReiniciar, &QAction::triggered, this, &MainWindow::accion_Reiniciar_triggered);
    connect(ui->actionSalir, &QAction::triggered, this, &QWidget::close);

    // Mapeo de filtros rapidos
    connect(ui->actionTCP, &QAction::triggered, this, [this](){aplicarFiltro("TCP");});
    connect(ui->actionUDP, &QAction::triggered, this, [this](){aplicarFiltro("UDP");});
    connect(ui->actionICMP, &QAction::triggered, this, [this](){aplicarFiltro("ICMP");});
    connect(ui->actionARP, &QAction::triggered, this, [this](){aplicarFiltro("ARP");});
    connect(ui->actionHTTP, &QAction::triggered, this, [this](){aplicarFiltro("HTTP");});
    connect(ui->actionHTTPS, &QAction::triggered, this, [this](){aplicarFiltro("HTTPS");});
    connect(ui->actionDNS, &QAction::triggered, this, [this](){aplicarFiltro("DNS");});
    connect(ui->actionIP, &QAction::triggered, this, [this](){aplicarFiltro("IP");});

    // excel
    connect(ui->actionExportar_CSV, &QAction::triggered, this, &MainWindow::on_btnExportarTodos_triggered);
    // Configuracion de la tabla de visualizacion de paquetes
    ui->tablePaquetes->setColumnCount(6);
    QStringList headers;
    // Cambiamos "Longitud" por "Info" en el titulo de la columna
    headers << "No." << "Tiempo" << "Origen" << "Destino" << "Protocolo" << "Info";

    ui->tablePaquetes->setHorizontalHeaderLabels(headers);
    ui->tablePaquetes->horizontalHeader()->setStretchLastSection(true);
    ui->tablePaquetes->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tablePaquetes->setSelectionBehavior(QAbstractItemView::SelectRows);

    connect(ui->tablePaquetes, &QTableWidget::itemClicked, this, &MainWindow::mostrarDetalles);

    // Timer para polling de actualizaciones en la UI
    timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &MainWindow::actualizarTabla);
}

MainWindow::~MainWindow()
{
    delete timer;
    delete captura;
    delete ui;
}

void MainWindow::cargarInterfaces()
{
    ui->interfaces->clear();
    auto lista = captura->obtenerInterfaces();

    for(const auto& nombre : lista)
    {
        ui->interfaces->addItem(QString::fromStdString(nombre));
    }
}

void MainWindow::iniciarCapturaDesdeLista() {
    QListWidgetItem* item = ui->interfaces->currentItem();
    if(!item) return;

    std::string nombreReal = captura->obtenerNombre(item->text().toStdString());

    if(captura->iniciar(nombreReal)) {
        timer->start(50);

        // Bloquear control para evitar colisiones de inicio multiple
        ui->interfaces->setEnabled(false);
    }
}

void MainWindow::accion_Iniciar_triggered(){
    if(captura) captura->reanudar();
    if(!timer->isActive()) timer->start(50);

    aplicarFiltro("");
}

void MainWindow::accion_Pausar_triggered(){
    if(captura) captura->pausar();
    if(timer) timer->stop();
}

void MainWindow::accion_Detener_triggered(){
    if(captura) captura->detener();
    if(timer) timer->stop();

    // Liberar UI para permitir una nueva captura
    ui->interfaces->setEnabled(true);
}

void MainWindow::accion_Reiniciar_triggered(){
    if(captura)
    {
        ui->tablePaquetes->setRowCount(0);
        ultimoPaqueteMostrado = 0;
        ui->tablePaquetes->clearContents();
        captura->reiniciar();
        aplicarFiltro("");

        ui->interfaces->setEnabled(true);
    }
}

void MainWindow::aplicarFiltro(const QString& protocoloFiltro)
{
    if(!captura) return;

    timer->stop();
    ui->tablePaquetes->setRowCount(0);

    std::string filtroStd = protocoloFiltro.toStdString();
    auto paquetesCapturados = captura->obtenerPaquetes()->obtener_todos();
    int filaVisual = 0;

    for(size_t i = 0; i < paquetesCapturados.size(); i++){
        bool cumpleFiltro = false;

        // Evaluacion de reglas de filtrado por protocolo/puerto
        if(protocoloFiltro.isEmpty()) { cumpleFiltro = true; }
        else if (filtroStd == "HTTP") { cumpleFiltro = (paquetesCapturados[i].puerto_org == 80 || paquetesCapturados[i].puerto_dst == 80); }
        else if (filtroStd == "HTTPS") { cumpleFiltro = (paquetesCapturados[i].puerto_org == 443 || paquetesCapturados[i].puerto_dst == 443); }
        else if (filtroStd == "DNS") { cumpleFiltro = (paquetesCapturados[i].puerto_org == 53 || paquetesCapturados[i].puerto_dst == 53); }
        else { cumpleFiltro = (paquetesCapturados[i].protocolo == filtroStd); }

        if(cumpleFiltro){
            ui->tablePaquetes->insertRow(filaVisual);

            QString protoStr = QString::fromStdString(paquetesCapturados[i].protocolo);
            QColor colorFondo = QColor(255, 255, 255); // Blanco por defecto

            // Asignacion de colores tipo Wireshark
            if (protoStr == "TCP") colorFondo = QColor(231, 230, 255);       // Morado claro
            else if (protoStr == "UDP") colorFondo = QColor(218, 238, 255);  // Azul claro
            else if (protoStr == "HTTP") colorFondo = QColor(228, 255, 199); // Verde claro
            else if (protoStr == "ICMP") colorFondo = QColor(252, 224, 255); // Rosa
            else if (protoStr == "ARP") colorFondo = QColor(214, 232, 255);  // Azul muy palido
            else if (protoStr == "DNS") colorFondo = QColor(218, 238, 255);

            // Obtener el resumen con banderas desde el parser
            QString infoStr = QString::fromStdString(paquetesCapturados[i].info_resumen);

            // Crear items de la tabla
            QTableWidgetItem* item[6];
            item[0] = new QTableWidgetItem(QString::number(paquetesCapturados[i].numero));
            item[1] = new QTableWidgetItem(QString::fromStdString(paquetesCapturados[i].tiempo));
            item[2] = new QTableWidgetItem(QString::fromStdString(paquetesCapturados[i].ip_org));
            item[3] = new QTableWidgetItem(QString::fromStdString(paquetesCapturados[i].ip_dst));
            item[4] = new QTableWidgetItem(protoStr);
            item[5] = new QTableWidgetItem(infoStr);

            // Aplicar el color a cada celda de la fila
            for(int c = 0; c < 6; c++){
                item[c]->setBackground(colorFondo);
                ui->tablePaquetes->setItem(filaVisual, c, item[c]);
            }
            filaVisual++;
        }
    }

    if(protocoloFiltro.isEmpty()){
        ultimoPaqueteMostrado = paquetesCapturados.size();
        timer->start(50);
    }
}

void MainWindow::actualizarTabla()
{
    if(!captura) return;
    auto paquetesCapturados = captura->obtenerPaquetes()->obtener_todos();

    // Insertar unicamente los paquetes nuevos desde el ultimo poll
    for(size_t i = ultimoPaqueteMostrado; i < paquetesCapturados.size(); i++)
    {
        int fila = ui->tablePaquetes->rowCount();
        ui->tablePaquetes->insertRow(fila);

        QString protoStr = QString::fromStdString(paquetesCapturados[i].protocolo);
        QColor colorFondo = QColor(255, 255, 255);
        QColor colorTexto = QColor(0, 0, 0);
        // Asignacion de colores tipo Wireshark
        if (protoStr == "TCP") colorFondo = QColor(60, 60, 160);
        else if (protoStr == "UDP") colorFondo = QColor(0, 150, 150);
        else if (protoStr == "HTTP") colorFondo = QColor(40, 120, 40);
        else if (protoStr == "ICMP") colorFondo = QColor(160, 40, 160);
        else if (protoStr == "ARP") colorFondo = QColor(160, 160, 40);
        else if (protoStr == "DNS") colorFondo = QColor(180, 100, 40);

        // Obtener el resumen con banderas desde el parser
        QString infoStr = QString::fromStdString(paquetesCapturados[i].info_resumen);

        QTableWidgetItem* item[6];
        item[0] = new QTableWidgetItem(QString::number(paquetesCapturados[i].numero));
        item[1] = new QTableWidgetItem(QString::fromStdString(paquetesCapturados[i].tiempo));
        item[2] = new QTableWidgetItem(QString::fromStdString(paquetesCapturados[i].ip_org));
        item[3] = new QTableWidgetItem(QString::fromStdString(paquetesCapturados[i].ip_dst));
        item[4] = new QTableWidgetItem(protoStr);
        item[5] = new QTableWidgetItem(infoStr);

        for(int c = 0; c < 6; c++){
            item[c]->setBackground(colorFondo);
            item[c]->setForeground(colorTexto);
            ui->tablePaquetes->setItem(fila, c, item[c]);
        }
    }

    ultimoPaqueteMostrado = paquetesCapturados.size();
    ui->tablePaquetes->scrollToBottom();

    if(ui->tablePaquetes->currentRow() == -1 && ui->tablePaquetes->rowCount() > 0)
    {
        ui->tablePaquetes->selectRow(0);
    }
}

void MainWindow::mostrarDetalles()
{
    if(!captura) return;

    int fila = ui->tablePaquetes->currentRow();
    if(fila < 0) return;

    int idPaqueteReal = ui->tablePaquetes->item(fila, 0)->text().toInt();
    auto paquetesCapturados = captura->obtenerPaquetes()->obtener_todos();

    PacketInfo pkt;
    bool encontrado = false;
    for(const auto& p : paquetesCapturados){
        if(p.numero == idPaqueteReal){
            pkt = p;
            encontrado = true;
            break;
        }
    }

    if(!encontrado) return;

    ui->treeDetalles->clear();

    // Nivel 1: Trama
    QTreeWidgetItem* frame = new QTreeWidgetItem(ui->treeDetalles);
    frame->setText(0, QString("Frame %1: %2 bytes").arg(pkt.numero).arg(pkt.longitud));

    // Nivel 2: Enlace (Ethernet)
    QTreeWidgetItem* eth = new QTreeWidgetItem(ui->treeDetalles);
    eth->setText(0, QString("Ethernet II"));
    new QTreeWidgetItem(eth, QStringList() << ("Source: " + QString::fromStdString(pkt.mac_org)));
    new QTreeWidgetItem(eth, QStringList() << ("Destination: " + QString::fromStdString(pkt.mac_dst)));

    // Nivel 3: Red (IP)
    QTreeWidgetItem* ip = new QTreeWidgetItem(ui->treeDetalles);
    ip->setText(0, "Internet Protocol");
    new QTreeWidgetItem(ip, QStringList() << ("Source: " + QString::fromStdString(pkt.ip_org)));
    new QTreeWidgetItem(ip, QStringList() << ("Destination: " + QString::fromStdString(pkt.ip_dst)));
    new QTreeWidgetItem(ip, QStringList() << ("TTL: " + QString::number(pkt.ttl)));

    // Nivel 4: Transporte/Aplicacion
    QTreeWidgetItem* proto = new QTreeWidgetItem(ui->treeDetalles);
    proto->setText(0, QString::fromStdString(pkt.protocolo));
    new QTreeWidgetItem(proto, QStringList() << ("Puerto origen: " + QString::number(pkt.puerto_org)));
    new QTreeWidgetItem(proto, QStringList() << ("Puerto destino: " + QString::number(pkt.puerto_dst)));

    mostrarHex(pkt);
}

void MainWindow::mostrarHex(const PacketInfo& pkt)
{
    QString salida;

    // Generacion de hexdump en formato estandar de 16 bytes por linea
    for(size_t i = 0; i < pkt.bytes.size(); i += 16)
    {
        salida += QString("%1   ").arg(i, 4, 16, QChar('0')).toUpper();
        QString hexParte;
        QString asciiParte;

        for(size_t j = 0; j < 16; j++)
        {
            if(i + j < pkt.bytes.size())
            {
                uint8_t byte = pkt.bytes[i + j];
                hexParte += QString("%1 ").arg(byte, 2, 16, QChar('0')).toUpper();

                // Imprimir caracter si es imprimible, de lo contrario '.'
                if(byte >= 32 && byte <= 126) asciiParte += QChar(byte);
                else asciiParte += ".";
            }
            else
            {
                hexParte += "   ";
                asciiParte += " ";
            }
        }
        salida += hexParte + "   " + asciiParte + "\n";
    }

    ui->txtHex->setPlainText(salida);
}
    void MainWindow::on_btnExportarTodos_triggered() {
        qDebug() << "¡Sí entró al botón de exportar!";
        if (timer->isActive()) {
            QMessageBox::warning(this, "Captura Activa",
                                 "¡Aguanta! Detén la captura de red primero antes de exportar a Excel para no corromper los datos.");
            return; // Cortamos la función aquí para que no exporte
        }

        std::vector<PacketInfo> datosCapturados = paquetes.obtener_todos();

        // 2. EXTRA: Validar que no vayas a exportar un Excel en blanco.
        if (datosCapturados.empty()) {
            QMessageBox::information(this, "Lista Vacía",
                                     "No hay ningún paquete capturado todavía.");
            return;
        }

        // 3. Si todo está bien, ahora sí armamos el Excel.
        exportarAExcelMultiplataforma(datosCapturados);

        // Opcional: Avisar que ya terminó
        QMessageBox::information(this, "Éxito", "¡Captura exportada al cien!");
    }
