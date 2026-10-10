/* The dependency has no Python imports or initialization hooks. */
__attribute__((visibility("default"))) long
glue_python_dependency_answer(void)
{
    return 42;
}
