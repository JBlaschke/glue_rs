parent_value = 42


def native_answer():
    from .glue_native_lifecycle import answer
    return answer()
