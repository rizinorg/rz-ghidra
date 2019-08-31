/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2GhidraDecompiler.h"

#include <Cutter.h>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

R2GhidraDecompiler::R2GhidraDecompiler(QObject *parent)
	: Decompiler("r2ghidra", "Ghidra", parent)
{
	task = nullptr;
}

void R2GhidraDecompiler::decompileAt(RVA addr)
{
	if(task)
		return;

	AnnotatedCode code = {};

	task = new R2Task ("pdgj @ " + QString::number(addr));

	connect(task, &R2Task::finished, this, [this]() {
		AnnotatedCode code = {};
		QString s;

		QJsonObject json = task->getResultJson().object();
		delete task;
		task = nullptr;
		if(json.isEmpty())
		{
			code.code = tr("Failed to parse JSON from r2ghidra");
			emit finished(code);
			return;
		}

		auto root = json;
		code.code = root["code"].toString();

		for(QJsonValueRef annotationValue : root["annotations"].toArray())
		{
			QJsonObject annotationObject = annotationValue.toObject();
			CodeAnnotation annotation = {};
			annotation.start = (size_t)annotationObject["start"].toVariant().toULongLong();
			annotation.end = (size_t)annotationObject["end"].toVariant().toULongLong();
			if(annotationObject["type"].toString() == "offset")
			{
				annotation.type = CodeAnnotation::Type::Offset;
				annotation.offset.offset = annotationObject["offset"].toVariant().toULongLong();
			}
			else
				continue;
			code.annotations.push_back(annotation);
		}
		emit finished(code);
	});
	task->startTask();

}
