
#include "AnnotatedCode.h"

#include <r_util.h>

R_API RAnnotatedCode *r_annotated_code_new(char *code)
{
	RAnnotatedCode *r = R_NEW0 (RAnnotatedCode);
	if (!r) {
		return NULL;
	}
	r->code = code;
	r_vector_init (&r->annotations, sizeof(RCodeAnnotation), NULL, NULL);
	return r;
}

R_API void r_annotated_code_free(RAnnotatedCode *code)
{
	r_vector_clear (&code->annotations);
	r_free (code->code);
	r_free (code);
}

R_API void r_annotated_code_add_annotation(RAnnotatedCode *code, RCodeAnnotation *annotation)
{
	r_vector_push (&code->annotations, annotation);
}

R_API RPVector *r_annotated_code_annotations_in(RAnnotatedCode *code, size_t offset)
{
	RPVector *r = r_pvector_new (NULL);
	if (!r) {
		return NULL;
	}
	RCodeAnnotation *annotation;
	r_vector_foreach (&code->annotations, annotation) {
		if (offset >= annotation->start && offset < annotation->end) {
			r_pvector_push (r, annotation);
		}
	}
	return r;
}