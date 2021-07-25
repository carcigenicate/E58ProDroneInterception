from collections import Callable

CommandMapping = dict[str, Callable]


# FIXME: Currently, Python's type hinting is too primitive to properly annotate Commands of different arities.
#  Unless every command takes the same arguments, it will cause a type error to be raised (TypeVar behavior).
def mapping_from_named_functions(commands) -> CommandMapping:
    """Returns a mapping where the keys are taken from the __name__ attribute of each function."""
    return {command.__name__: command for command in commands}