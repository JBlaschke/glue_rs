#include "ledger.h"
#include <stdio.h>
#include <string.h>

static int expect(long actual, long expected)
{
    if (actual != expected) {
        fprintf(stderr, "ledger unit result %ld differs from %ld\n", actual, expected);
        return 0;
    }
    return 1;
}

static long allocate(long root)
{
    if (glue_python_lifecycle_ledger(GLUE_LIFECYCLE_INIT, root, 0) < 1 ||
        glue_python_lifecycle_ledger(GLUE_LIFECYCLE_CREATE, root, 0) < 1 ||
        glue_python_lifecycle_ledger(GLUE_LIFECYCLE_CREATED, root, 0) < 1) {
        return -1;
    }
    return glue_python_lifecycle_ledger(GLUE_LIFECYCLE_ALLOCATE, root, 0);
}

static int complete(void)
{
    const long owners[5] = {1, 1, 2, 3, 3};
    for (long index = 0; index < 5; index++) {
        long root = owners[index];
        if (root == 2) {
            if (!expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_INIT, root, 0), 1) ||
                !expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_CREATE, root, 0), 1)) return 0;
        }
        long id = allocate(root);
        if (!expect(id, index + 1) ||
            !expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_OWN, root, id), 0) ||
            glue_python_lifecycle_ledger(GLUE_LIFECYCLE_TRAVERSE, root, id) < 1) return 0;
        if (index == 0 && !expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_CLEAR, root, id), 1)) return 0;
        if (!expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_RELEASE, root, id), 0) ||
            !expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_FREE, root, id), 0)) return 0;
    }
    return expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_CHECK, 0, 0), 0) &&
           expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_QUERY, 0, GLUE_LIFECYCLE_ALLOCATIONS), 5) &&
           expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_QUERY, 0, GLUE_LIFECYCLE_FREES), 5) &&
           expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_QUERY, 0, GLUE_LIFECYCLE_OWNED), 0);
}

int main(int argc, char **argv)
{
    if (argc != 2) return 1;
    if (strcmp(argv[1], "complete") == 0) return complete() ? 0 : 1;
    if (strcmp(argv[1], "duplicate-free") == 0) {
        return complete() &&
               expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_FREE, 1, 1), -1) &&
               expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_CHECK, 0, 0), -1) ? 0 : 1;
    }
    if (strcmp(argv[1], "capacity") == 0) {
        for (long index = 1; index <= GLUE_LIFECYCLE_RECORDS; index++) {
            if (!expect(allocate(1), index)) return 1;
        }
        return expect(allocate(1), -1) &&
               expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_QUERY, 0, GLUE_LIFECYCLE_ALLOCATIONS), GLUE_LIFECYCLE_RECORDS) &&
               expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_QUERY, 0, GLUE_LIFECYCLE_ERRORS), 1) ? 0 : 1;
    }
    long id = allocate(1);
    if (!expect(id, 1)) return 1;
    if (strcmp(argv[1], "incomplete") == 0) {
        return expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_CHECK, 0, 0), -1) ? 0 : 1;
    }
    if (strcmp(argv[1], "wrong-root") == 0) {
        return expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_FREE, 2, id), -1) &&
               expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_QUERY, 0, GLUE_LIFECYCLE_FREES), 0) ? 0 : 1;
    }
    if (!expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_OWN, 1, id), 0)) return 1;
    if (strcmp(argv[1], "duplicate-own") == 0) {
        return expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_OWN, 1, id), -1) ? 0 : 1;
    }
    if (strcmp(argv[1], "owned-free") == 0) {
        return expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_FREE, 1, id), -1) &&
               expect(glue_python_lifecycle_ledger(GLUE_LIFECYCLE_QUERY, 0, GLUE_LIFECYCLE_OWNED), 1) ? 0 : 1;
    }
    return 1;
}
