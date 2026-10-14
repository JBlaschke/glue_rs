#include "ledger.h"

typedef struct {
    long root;
    long live;
    long owned;
    long ownerships;
    long releases;
    long frees;
    long traversals;
    long clears;
} Record;

typedef struct {
    long inits;
    long creates;
    long created;
    long allocated;
    long last_id;
} Root;

static Record records[GLUE_LIFECYCLE_RECORDS];
static Root roots[3];
static long allocated;
static long errors;

static long reject(void)
{
    if (errors < 1000000) {
        errors++;
    }
    return -1;
}

static long increment(long *value)
{
    if (*value >= 1000000) {
        return reject();
    }
    return ++*value;
}

static long query(long root, long field)
{
    long result = 0;
    if (field < GLUE_LIFECYCLE_ALLOCATIONS || field > GLUE_LIFECYCLE_LAST_ID) {
        return reject();
    }
    if (field == GLUE_LIFECYCLE_ERRORS) {
        return errors;
    }
    for (long index = 0; index < 3; index++) {
        if (root == 0 || root == index + 1) {
            if (field == GLUE_LIFECYCLE_INITS) result += roots[index].inits;
            if (field == GLUE_LIFECYCLE_CREATES) result += roots[index].creates;
            if (field == GLUE_LIFECYCLE_CREATED_OBJECTS) result += roots[index].created;
            if (field == GLUE_LIFECYCLE_LAST_ID && roots[index].last_id > result) result = roots[index].last_id;
        }
    }
    for (long index = 0; index < allocated; index++) {
        Record *record = &records[index];
        if (root == 0 || root == record->root) {
            if (field == GLUE_LIFECYCLE_ALLOCATIONS) result++;
            if (field == GLUE_LIFECYCLE_FREES) result += record->frees;
            if (field == GLUE_LIFECYCLE_OWNED) result += record->owned;
            if (field == GLUE_LIFECYCLE_RELEASES) result += record->releases;
            if (field == GLUE_LIFECYCLE_TRAVERSALS) result += record->traversals;
            if (field == GLUE_LIFECYCLE_CLEARS) result += record->clears;
        }
    }
    return result;
}

static long check(void)
{
    if (errors != 0 || allocated != 5 ||
        query(0, GLUE_LIFECYCLE_CLEARS) == 0) {
        return -1;
    }
    for (long index = 0; index < 3; index++) {
        long expected = index == 1 ? 1 : 2;
        if (roots[index].inits != 2 || roots[index].creates != 2 ||
            roots[index].created != expected || roots[index].allocated != expected) {
            return -1;
        }
    }
    for (long index = 0; index < allocated; index++) {
        Record *record = &records[index];
        if (record->live || record->owned || record->ownerships != 1 ||
            record->releases != 1 || record->frees != 1 || record->traversals == 0) {
            return -1;
        }
    }
    return 0;
}

long glue_python_lifecycle_ledger(long op, long root, long instance)
{
    if (root < 0 || root > 3) {
        return reject();
    }
    if (op == GLUE_LIFECYCLE_QUERY) {
        return query(root, instance);
    }
    if (op == GLUE_LIFECYCLE_CHECK) {
        return root == 0 && instance == 0 ? check() : reject();
    }
    if (root == 0) {
        return reject();
    }
    Root *selected = &roots[root - 1];
    if (op == GLUE_LIFECYCLE_INIT && instance == 0) {
        return increment(&selected->inits);
    }
    if (op == GLUE_LIFECYCLE_CREATE && instance == 0 &&
        selected->creates < selected->inits) {
        return increment(&selected->creates);
    }
    if (op == GLUE_LIFECYCLE_CREATED && instance == 0 &&
        selected->created < selected->creates) {
        return increment(&selected->created);
    }
    if (op == GLUE_LIFECYCLE_ALLOCATE && instance == 0 &&
        allocated < GLUE_LIFECYCLE_RECORDS && selected->allocated < selected->created) {
        Record *record = &records[allocated++];
        record->root = root;
        record->live = 1;
        selected->allocated++;
        selected->last_id = allocated;
        return allocated;
    }
    if (instance < 1 || instance > allocated) {
        return reject();
    }
    Record *record = &records[instance - 1];
    if (record->root != root || !record->live) {
        return reject();
    }
    switch (op) {
        case GLUE_LIFECYCLE_OWN:
            if (record->ownerships || record->owned) return reject();
            record->ownerships = record->owned = 1;
            return 0;
        case GLUE_LIFECYCLE_TRAVERSE:
            return increment(&record->traversals);
        case GLUE_LIFECYCLE_CLEAR:
            return increment(&record->clears);
        case GLUE_LIFECYCLE_RELEASE:
            if (!record->owned || record->releases) return reject();
            record->owned = 0;
            record->releases = 1;
            return 0;
        case GLUE_LIFECYCLE_FREE:
            if (record->owned || record->frees) return reject();
            record->live = 0;
            record->frees = 1;
            return 0;
        default:
            return reject();
    }
}
