#include "widget.h"
#include "ui_widget.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QMimeData>
#include <QDropEvent>
#include <QTranslator>
#include <QAction>
#include <QSignalMapper>
#include <QEvent>
#include "cfgfile.h"
#include "ctce8cfgfile.h"

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
    setContextMenuPolicy(Qt::ActionsContextMenu);
    language = new QTranslator;
    g_language= new QTranslator;
    QSignalMapper *sign_mapper = new QSignalMapper(this);
    chinese = new QAction(tr("中文"), this);
    english = new QAction(tr("English"), this);
    QAction *separator = new QAction(this);
    separator->setSeparator(true);
    about = new QAction(tr("About"), this);
    addAction(chinese);
    addAction(english);
    addAction(separator);
    addAction(about);
    sign_mapper->setMapping(chinese, 1);
    sign_mapper->setMapping(english, 2);
    sign_mapper->setMapping(about, 3);
    connect(chinese, SIGNAL(triggered(bool)), sign_mapper, SLOT(map()));
    connect(english, SIGNAL(triggered(bool)), sign_mapper, SLOT(map()));
    connect(about, SIGNAL(triggered(bool)), sign_mapper, SLOT(map()));
    connect(sign_mapper, SIGNAL(mapped(int)), this, SLOT(update_ui(int)));
    QLocale locale;
    if (locale.language() == QLocale::Chinese) update_ui(1);
}

Widget::~Widget()
{
    delete ui;
}

void Widget::dropEvent(QDropEvent *event)
{
    const QMimeData *mimedata = event->mimeData();
    if (mimedata->hasUrls()) {
        ui->cfg_line_edit_->setText(mimedata->urls()[0].toLocalFile());
    } else  {
        ui->cfg_line_edit_->setText(mimedata->text());
    }
}

void Widget::dragEnterEvent(QDragEnterEvent *event)
{
    const QMimeData *mimedata = event->mimeData();
    QString filename;
    if (mimedata->hasUrls()) {
        filename = mimedata->urls()[0].toLocalFile();
        if (filename.right(4) == ".cfg")
            event->acceptProposedAction();
    } else if (mimedata->hasHtml()) {
        filename = mimedata->text();
        if (filename.right(4) == ".cfg")
            event->acceptProposedAction();
    }
}

void Widget::on_cfg_en_button__clicked()
{
    int result;
    QString file = ui->cfg_line_edit_->text();
    if (file.isEmpty()) {
        QMessageBox::warning(this, tr("Warning"), tr("Please specify the CFG file."));
        return ;
    }
    QFileInfo file_info(file);
    if (!file_info.isFile()) {
        QMessageBox::warning(this, tr("Warning"), tr("The specified CFG file does not exist."));
        return ;
    }

    QString old_file = file;
    old_file.replace(file_info.absolutePath().size()+1, file_info.fileName().size(), "old_"+file_info.fileName());
    QFile::rename(file, old_file);

    switch (ui->cfg_type_combo_box_->currentIndex()) {
    case TYPE::CTCE:
    {
        if (ui->ver_line_edit_->text().isEmpty()) {
            QFile::remove(file);
            QFile::rename(old_file, file);
            QMessageBox::warning(this, tr("Warning"), tr("CTCE encryption must specify a version."));
            return ;
        }
        Ctce8CfgFile a(old_file);
        result = a.encrypt(file, ui->ver_line_edit_->text());
    }
        break;
    default:
    {
        CfgFile a(old_file);
        result = a.encrypt(file);
    }
        break;
    }

    if (result != 1) {
        QFile::remove(file);
        QFile::rename(old_file, file);
        QMessageBox::critical(this, tr("Error"), tr("An unknown error."));
        return ;
    }
}

void Widget::on_cfg_de_button__clicked()
{
    int result;
    QString file = ui->cfg_line_edit_->text();
    if (file.isEmpty()) {
        QMessageBox::warning(this, tr("Warning"), tr("Please specify the CFG file."));
        return ;
    }
    QFileInfo file_info(file);
    if (!file_info.isFile()) {
        QMessageBox::warning(this, tr("Warning"), tr("The specified CFG file does not exist."));
        return ;
    }
    QString old_file = file;
    old_file.replace(file_info.absolutePath().size()+1, file_info.fileName().size(), "old_"+file_info.fileName());
    QFile::rename(file, old_file);

    switch (ui->cfg_type_combo_box_->currentIndex()) {
    case TYPE::CTCE:
    {
        Ctce8CfgFile a(old_file);
        result = a.decrypt(file);
    }
        break;
    default:
    {
        CfgFile a(old_file);
        result = a.decrypt(file);
    }
        break;
    }

    if (result != 1) {
        QFile::remove(file);
        QFile::rename(old_file, file);
        QMessageBox::critical(this, tr("Error"), tr("An unknown error."));
        return ;
    }
}

void Widget::on_cfg_tool_button__clicked()
{
    QString file = QFileDialog::getOpenFileName(this, tr("Open File"), NULL, tr("CFG File(*.cfg)"));
    if (file.isEmpty()) return ;
    ui->cfg_line_edit_->setText(file);
}

void Widget::update_ui(int i)
{
    if (i == 1) {
        language->load(":/language/chinese.qm");
        g_language->load(":/language/qt_zh_CN.qm");
        qApp->installTranslator(language);
        qApp->installTranslator(g_language);
        about->setText("关于");
        ui->retranslateUi(this);
    }else if (i == 2) {
        qApp->removeTranslator(language);
        qApp->removeTranslator(g_language);
        about->setText("About");
        ui->retranslateUi(this);
    }else if (i == 3) {
        QMessageBox::about(this, tr("About"), tr("Please don't used for illegal purposes\nBy:欲断魂\nVersion:1.0"));
    }
}

void Widget::on_cfg_type_combo_box__activated(int index)
{
    if (index == 1) {
        ui->ver_label_->setEnabled(true);
        ui->ver_line_edit_->setEnabled(true);
    } else {
        ui->ver_label_->setEnabled(false);
        ui->ver_line_edit_->setEnabled(false);
    }
}
