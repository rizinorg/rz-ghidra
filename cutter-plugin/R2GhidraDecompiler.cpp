/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "R2GhidraDecompiler.h"

#include <Cutter.h>

#include <QtXml>

R2GhidraDecompiler::R2GhidraDecompiler(QObject *parent)
	: Decompiler("r2ghidra", "Ghidra", parent)
{
}

AnnotatedCode R2GhidraDecompiler::decompileAt(RVA addr)
{
	AnnotatedCode code = {};

	auto json = Core()->cmd("pdgj @ " + QString::number(addr));
	if(json.isEmpty())
		return code;

	QJsonParseError jsonError;
	QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8(), &jsonError);
	if(jsonError.error != QJsonParseError::NoError)
	{
		// Dirty but ENOTIME
		code.code = json;
		return code;
	}

	auto root = doc.object();
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

	return code;
}
