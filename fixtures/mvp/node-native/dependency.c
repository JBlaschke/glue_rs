static int constructors;
static _Thread_local int calls;
__attribute__((constructor)) static void start(void){constructors++;}
int probe_answer(void){calls++;return 42;}
int probe_constructors(void){return constructors;}
