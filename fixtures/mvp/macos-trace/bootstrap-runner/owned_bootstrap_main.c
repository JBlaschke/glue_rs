#include "bootstrap_runner.h"
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv) {
    if(argc!=5 || strcmp(argv[1],"--request") || strcmp(argv[3],"--output"))return 2;
    _exit(nr_native_run_once(argv[2],argv[4]));
}
