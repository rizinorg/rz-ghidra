// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZGHIDRAPLUGIN_H
#define RZGHIDRAPLUGIN_H

#include <QObject>
#include <QtPlugin>
#include <plugins/CutterPlugin.h>

class RzGhidraPlugin : public QObject, CutterPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.rizin.cutter.plugins.rz-ghidra")
    Q_INTERFACES(CutterPlugin)

public:
    void setupPlugin() override;
    void setupInterface(MainWindow *main) override;
    void registerDecompilers() override;

    QString getName() const          { return "Ghidra Decompiler (rz-ghidra)"; }
    QString getAuthor() const        { return "thestr4ng3r"; }
    QString getDescription() const   { return "GUI Integration of rz-ghidra."; }
    QString getVersion() const       { return "1.0"; }
};


#endif // CUTTERSAMPLEPLUGIN_H
