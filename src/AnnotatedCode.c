
#include "AnnotatedCode.h"

#include <r_util.h>
#include <r_cons.h>

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

R_API void r_annotated_code_print_json(RAnnotatedCode *code)
{
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}

	pj_o (pj);
	pj_ks (pj, "code", code->code);

	pj_k (pj, "annotations");
	pj_a (pj);
	RCodeAnnotation *annotation;
	r_vector_foreach (&code->annotations, annotation) {
		pj_o (pj);
		pj_kn (pj, "start", (ut64)annotation->start);
		pj_kn (pj, "end", (ut64)annotation->end);
		switch (annotation->type) {
		case R_CODE_ANNOTATION_TYPE_OFFSET:
			pj_ks (pj, "type", "offset");
			pj_kn (pj, "offset", annotation->offset.offset);
			break;
		}
		pj_end (pj);
	}
	pj_end (pj);

	pj_end (pj);
	r_cons_printf ("%s", pj_string (pj));
	pj_free (pj);
}
