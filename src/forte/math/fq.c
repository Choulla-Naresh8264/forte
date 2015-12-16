struct finite_field {
    fq_ctx_t context;
};

struct finite_field_element
    fmpz_poly_t element;
};

// TODO: names...
typedef struct finite_field Fq;
typedef struct finite_field_element FqE;

FqE *
ffq_CreateElement(Fq* field)
{
    return NULL;
}


