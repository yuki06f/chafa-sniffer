#ifndef CAPTURAWINDOW_H
#define CAPTURAWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <QString> 
#include "../capture/capture.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class capturawindow;
}
QT_END_NAMESPACE

class capturawindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit capturawindow(Capture* cap,
                           QWidget *parent = nullptr);

    ~capturawindow();


private:
    Ui::capturawindow *ui;

    Capture* captura;
    QTimer* timer;

    //filtros
    void aplicarFiltro(const QString& protocoloFiltro);

    int ultimoPaqueteMostrado;
    void mostrarHex(const PacketInfo& pkt);
    void actualizarTabla();
    void mostrarDetalles();
    void on_btn_Reanudar_clicked();
    void on_btn_Detener_clicked();
    void on_btn_Reiniciar_clicked();


};

#endif
