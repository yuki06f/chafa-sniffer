#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <QString>
#include <QTreeWidgetItem>
#include "../capture/capture.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    // Lógica de la interfaz
    void cargarInterfaces();
    void iniciarCapturaDesdeLista();

    // Controles de captura (Controlados por tu QMenuBar)
    void accion_Iniciar_triggered();
    void accion_Detener_triggered();
    void accion_Reiniciar_triggered();

    // Actualización y visualización
    void actualizarTabla();
    void mostrarDetalles();

private:
    Ui::MainWindow *ui;

    // Variables base
    PacketCatched paquetes;
    Capture* captura;
    QTimer* timer;

    // Lógica de Filtros
    void aplicarFiltro(const QString& protocoloFiltro);

    // Variables y lógica de visualización
    int ultimoPaqueteMostrado;
    void mostrarHex(const PacketInfo& pkt);
};

#endif // MAINWINDOW_H