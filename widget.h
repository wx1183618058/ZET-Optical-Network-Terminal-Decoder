#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>

class QTranslator;
class QAction;

namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = 0);
    ~Widget();

protected:
    void dropEvent(QDropEvent *event);
    void dragEnterEvent(QDragEnterEvent *event);

private slots:
    void on_cfg_en_button__clicked();
    void on_cfg_de_button__clicked();
    void on_cfg_tool_button__clicked();
    void update_ui(int i);

    void on_cfg_type_combo_box__activated(int index);

private:
    Ui::Widget *ui;
    QTranslator *language;
    QTranslator *g_language;
    QAction *chinese;
    QAction *english;
    QAction *about;
    enum TYPE {
        Default = 0,
        CTCE
    };
};

#endif // WIDGET_H
