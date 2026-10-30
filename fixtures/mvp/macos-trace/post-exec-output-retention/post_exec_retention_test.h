#ifndef GLUE_POST_EXEC_RETENTION_TEST_H
#define GLUE_POST_EXEC_RETENTION_TEST_H
#ifndef PXRET_TESTING
#error private retention controls require PXRET_TESTING
#endif
#include "post_exec_retention.h"
#include <sys/stat.h>
#include <sys/types.h>
/* Explicitly untrusted model seams. The real observer encoder/owns APIs are
 * never replaced. Production exposes only its fixed native constructor. */
struct px_retention_test_operations {
 void *context;
 pid_t (*owner_fn)(void *);
 uid_t (*uid_fn)(void *);
 int (*clock_fn)(void *,uint64_t *,int *);
 int (*flags_fn)(void *,int,int,int *);
 int (*stat_fn)(void *,int,struct stat *,int *);
 int (*open_fn)(void *,int,const char *,int,mode_t,int *);
 ssize_t (*write_fn)(void *,int,const void *,size_t,int *);
 int (*sync_fn)(void *,int,int *);
 int (*close_fn)(void *,int,int *);
};
struct px_retention *px_retention_model_new(const struct px_observer *,int,uint64_t,
 const struct px_retention_test_operations *,struct px_retention_error *);
#endif
