#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "../filters/filter_engine.h"
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , ultimoPaqueteMostrado(0)
{
    ui->setupUi(this);

    // 1. Inicializar la Captura
    captura = new Capture(&paquetes);

    // 2. Cargar interfaces en la lista
    cargarInterfaces();

    // Conectar el doble clic de la lista para iniciar captura
    connect(ui->interfaces, &QListWidget::itemDoubleClicked,
            this, &MainWindow::iniciarCapturaDesdeLista);

    // === CONEXIONES DE LA BARRA DE MENÚ (QActions) ===

    // Controles principales
    connect(ui->actionIniciar_Captura, &QAction::triggered, this, &MainWindow::accion_Iniciar_triggered);
    connect(ui->actionDetener, &QAction::triggered, this, &MainWindow::accion_Detener_triggered);
    connect(ui->actionReiniciar, &QAction::triggered, this, &MainWindow::accion_Reiniciar_triggered);

    // Salir del programa
    connect(ui->actionSalir, &QAction::triggered, this, &QWidget::close);

    // Filtros desde el Menú
    connect(ui->actionTCP, &QAction::triggered, this, [this](){aplicarFiltro("TCP");});
    connect(ui->actionUDP, &QAction::triggered, this, [this](){aplicarFiltro("UDP");});
    connect(ui->actionICMP, &QAction::triggered, this, [this](){aplicarFiltro("ICMP");});
    connect(ui->actionARP, &QAction::triggered, this, [this](){aplicarFiltro("ARP");});
    connect(ui->actionHTTP, &QAction::triggered, this, [this](){aplicarFiltro("HTTP");});
    connect(ui->actionHTTPS, &QAction::triggered, this, [this](){aplicarFiltro("HTTPS");});
    connect(ui->actionDNS, &QAction::triggered, this, [this](){aplicarFiltro("DNS");});
    connect(ui->actionIP, &QAction::triggered, this, [this](){aplicarFiltro("IP");});
    // Nota: Como en tu .ui no vi un botón "actionTodos" para quitar filtros,
    // te recomiendo añadir uno en Qt Designer y conectarlo usando: aplicarFiltro("");

    // === CONFIGURAR TABLA ===
    ui->tablePaquetes->setColumnCount(6);

    QStringList headers;
    headers << "No." << "Tiempo" << "Origen" << "Destino" << "Protocolo" << "Longitud";

    ui->tablePaquetes->setHorizontalHeaderLabels(headers);
    ui->tablePaquetes->horizontalHeader()->setStretchLastSection(true);
    ui->tablePaquetes->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tablePaquetes->setSelectionBehavior(QAbstractItemView::SelectRows);

    connect(ui->tablePaquetes, &QTableWidget::itemClicked, this, &MainWindow::mostrarDetalles);

    // === CONFIGURAR TIMER ===
    timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &MainWindow::actualizarTabla);
}

MainWindow::~MainWindow()
{
    delete timer;
    delete captura;
    delete ui;
}

// === LÓGICA DE INTERFACES ===
void MainWindow::cargarInterfaces()
{
    ui->interfaces->clear();
    auto lista = captura->obtenerInterfaces();

    for(const auto& nombre : lista)
    {
        ui->interfaces->addItem(QString::fromStdString(nombre));
    }
}

void MainWindow::iniciarCapturaDesdeLista()
{
    QListWidgetItem* item = ui->interfaces->currentItem();
    if(!item) return;

    std::string nombreReal = captura->obtenerNombre(item->text().toStdString());

    if(captura->iniciar(nombreReal))
    {
        timer->start(50);
    }
}

// === ACCIONES DE LA BARRA DE MENÚ ===
void MainWindow::accion_Iniciar_triggered(){
    // Si la captura estaba pausada, la reanudamos
    if(captura) captura->reanudar();
    if(!timer->isActive()) timer->start(50);

    aplicarFiltro(""); // Quita los filtros para seguir visualizando todo
}

void MainWindow::accion_Detener_triggered(){
    if(captura) captura->pausar();
    if(timer) timer->stop();
}

void MainWindow::accion_Reiniciar_triggered(){
    if(captura)
    {
        ui->tablePaquetes->setRowCount(0);
        ultimoPaqueteMostrado = 0;
        ui->tablePaquetes->clearContents();
        captura->reiniciar();
        aplicarFiltro("");
    }
}

// === LÓGICA DE FILTROS ===
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

        if(protocoloFiltro.isEmpty()) { cumpleFiltro = true; }
        else if (filtroStd == "HTTP") { cumpleFiltro = (paquetesCapturados[i].puerto_org == 80 || paquetesCapturados[i].puerto_dst == 80); }
        else if (filtroStd == "HTTPS") { cumpleFiltro = (paquetesCapturados[i].puerto_org == 443 || paquetesCapturados[i].puerto_dst == 443); }
        else if (filtroStd == "DNS") { cumpleFiltro = (paquetesCapturados[i].puerto_org == 53 || paquetesCapturados[i].puerto_dst == 53); }
        else { cumpleFiltro = (paquetesCapturados[i].protocolo == filtroStd); }

        if(cumpleFiltro){
            ui->tablePaquetes->insertRow(filaVisual);
            ui->tablePaquetes->setItem(filaVisual, 0, new QTableWidgetItem(QString::number(paquetesCapturados[i].numero)));
            ui->tablePaquetes->setItem(filaVisual, 1, new QTableWidgetItem(QString::fromStdString(paquetesCapturados[i].tiempo)));
            ui->tablePaquetes->setItem(filaVisual, 2, new QTableWidgetItem(QString::fromStdString(paquetesCapturados[i].ip_org)));
            ui->tablePaquetes->setItem(filaVisual, 3, new QTableWidgetItem(QString::fromStdString(paquetesCapturados[i].ip_dst)));
            ui->tablePaquetes->setItem(filaVisual, 4, new QTableWidgetItem(QString::fromStdString(paquetesCapturados[i].protocolo)));
            ui->tablePaquetes->setItem(filaVisual, 5, new QTableWidgetItem(QString::number(paquetesCapturados[i].longitud)));
            filaVisual++;
        }
    }

    if(protocoloFiltro.isEmpty()){
        ultimoPaqueteMostrado = paquetesCapturados.size();
        timer->start(50);
    }
}

// === ACTUALIZACIÓN DE TABLA ===
void MainWindow::actualizarTabla()
{
    if(!captura) return;
    auto paquetesCapturados = captura->obtenerPaquetes()->obtener_todos();

    for(size_t i = ultimoPaqueteMostrado; i < paquetesCapturados.size(); i++)
    {
        int fila = ui->tablePaquetes->rowCount();
        ui->tablePaquetes->insertRow(fila);
        ui->tablePaquetes->setItem(fila,0, new QTableWidgetItem(QString::number(paquetesCapturados[i].numero)));
        ui->tablePaquetes->setItem(fila,1, new QTableWidgetItem(QString::fromStdString(paquetesCapturados[i].tiempo)));
        ui->tablePaquetes->setItem(fila,2, new QTableWidgetItem(QString::fromStdString(paquetesCapturados[i].ip_org)));
        ui->tablePaquetes->setItem(fila,3, new QTableWidgetItem(QString::fromStdString(paquetesCapturados[i].ip_dst)));
        ui->tablePaquetes->setItem(fila,4, new QTableWidgetItem(QString::fromStdString(paquetesCapturados[i].protocolo)));
        ui->tablePaquetes->setItem(fila,5, new QTableWidgetItem(QString::number(paquetesCapturados[i].longitud)));
    }

    ultimoPaqueteMostrado = paquetesCapturados.size();
    ui->tablePaquetes->scrollToBottom();

    if(ui->tablePaquetes->currentRow() == -1 && ui->tablePaquetes->rowCount() > 0)
    {
        ui->tablePaquetes->selectRow(0);
    }
}

// === MOSTRAR DETALLES Y HEXADECIMAL ===
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

    QTreeWidgetItem* frame = new QTreeWidgetItem(ui->treeDetalles);
    frame->setText(0, QString("Frame %1: %2 bytes").arg(pkt.numero).arg(pkt.longitud));

    QTreeWidgetItem* eth = new QTreeWidgetItem(ui->treeDetalles);
    eth->setText(0, QString("Ethernet II"));
    new QTreeWidgetItem(eth, QStringList() << ("Source: " + QString::fromStdString(pkt.mac_org)));
    new QTreeWidgetItem(eth, QStringList() << ("Destination: " + QString::fromStdString(pkt.mac_dst)));

    QTreeWidgetItem* ip = new QTreeWidgetItem(ui->treeDetalles);
    ip->setText(0, "Internet Protocol");
    new QTreeWidgetItem(ip, QStringList() << ("Source: " + QString::fromStdString(pkt.ip_org)));
    new QTreeWidgetItem(ip, QStringList() << ("Destination: " + QString::fromStdString(pkt.ip_dst)));
    new QTreeWidgetItem(ip, QStringList() << ("TTL: " + QString::number(pkt.ttl)));

    QTreeWidgetItem* proto = new QTreeWidgetItem(ui->treeDetalles);
    proto->setText(0, QString::fromStdString(pkt.protocolo));
    new QTreeWidgetItem(proto, QStringList() << ("Puerto origen: " + QString::number(pkt.puerto_org)));
    new QTreeWidgetItem(proto, QStringList() << ("Puerto destino: " + QString::number(pkt.puerto_dst)));

    mostrarHex(pkt);
}

void MainWindow::mostrarHex(const PacketInfo& pkt)
{
    QString salida;
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