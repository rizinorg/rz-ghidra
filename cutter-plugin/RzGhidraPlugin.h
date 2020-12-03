// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef R2GHIDRAPLUGIN_H
#define R2GHIDRAPLUGIN_H

#include <QObject>
#include <QtPlugin>
#include <plugins/CutterPlugin.h>

class RzGhidraPlugin : public QObject, CutterPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.radare.cutter.plugins.r2ghidra")
    Q_INTERFACES(CutterPlugin)

public:
    void setupPlugin() override;
    void setupInterface(MainWindow *main) override;
    void registerDecompilers() override;

    QString getName() const          { return "Ghidra Decompiler (r2ghidra)"; }
    QString getAuthor() const        { return "thestr4ng3r"; }
    QString getDescription() const   { return "GUI Integration of r2ghidra."; }
    QString getVersion() const       { return "1.0"; }
};


#endif // CUTTERSAMPLEPLUGIN_H
