"""Source package used by the pinned archive distribution metadata profile."""

from importlib.resources import files


def plugin():
    assert files(__package__).joinpath("data/message,one.txt").read_text() == "archive metadata resource\n"
    return 42
