
#ifndef R2GHIDRA_ANNOTATEDCODE_H
#define R2GHIDRA_ANNOTATEDCODE_H

#include <r_types.h>
#include <r_vector.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum r_code_annotation_type_t {
	R_CODE_ANNOTATION_TYPE_OFFSET,
	// ...
} RCodeAnnotationType;

typedef struct r_code_annotation_t {
	size_t start;
	size_t end;
	RCodeAnnotationType type;
	union
	{
		struct
		{
			ut64 offset;
		} offset;
	};
} RCodeAnnotation;

typedef struct r_annotated_code_t {
	char *code; // owned
	RVector/*<RCodeAnnotation>*/ annotations;
} RAnnotatedCode;

R_API RAnnotatedCode *r_annotated_code_new(char *code);
R_API void r_annotated_code_free(RAnnotatedCode *code);
R_API void r_annotated_code_add_annotation(RAnnotatedCode *code, RCodeAnnotation *annotation);
R_API RPVector *r_annotated_code_annotations_in(RAnnotatedCode *code, size_t offset);
R_API void r_annotated_code_print_json(RAnnotatedCode *code);

#ifdef __cplusplus
}
#endif

#endif //R2GHIDRA_ANNOTATEDCODE_H
