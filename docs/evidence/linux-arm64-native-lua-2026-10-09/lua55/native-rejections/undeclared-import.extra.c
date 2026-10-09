extern void glue_forbidden_constructor(void);
__attribute__((constructor))
static void forbidden_constructor(void) {
    glue_forbidden_constructor();
}
