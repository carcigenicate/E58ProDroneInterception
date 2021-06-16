from __future__ import annotations
from functools import partial
from typing import Callable, Any, NamedTuple, Union
from inspect import getdoc, getfullargspec

HELP_PADDING_LENGTH = 4

DEFAULT_COMMAND_PRODUCER = partial(input, ":> ")
DEFAULT_RESULT_CONSUMER = print

Command = Callable[..., Any]
CommandMapping = dict[str, Command]


class FunctionHelp(NamedTuple):
    name: str
    parameters_and_defaults: list[Union[tuple[str], tuple[str, Any]]]
    docstring: str

    def __str__(self) -> str:
        """Produces formatted help text for the function the class instance describes."""
        header = f"{self.name}\n{self.docstring}"
        # TODO: Eww. Only include (default) if a default was included (the tuple has more than 1 element).
        raw_parameters = [f"{para_and_def[0]}{'' if len(para_and_def) < 2 else f' (default={para_and_def[1]!r})'}"
                          for para_and_def in self.parameters_and_defaults]
        pre = " " * HELP_PADDING_LENGTH
        parameters = "\n".join(f"{pre}{pre}{line}" for line in raw_parameters)
        parameter_header = f"{pre}Parameters:\n" if parameters else ''
        return f"{header}\n{parameter_header}{parameters}"

    @staticmethod
    def from_callable(callable: Callable) -> FunctionHelp:
        """Pulls the information from the function required to produce simple usage information.
        Only works with functions that don't use positional/keyword-only parameters.
        Handles the special-case of partial by returning information about the function that it wraps.
        Custom callable classes should define __name__ so the name can be included"""
        if isinstance(callable, partial):
            callable = callable.func
        name = getattr(callable, "__name__", "")

        arg_spec = getfullargspec(callable)
        defs = arg_spec.defaults or []
        fst_def_i = len(arg_spec.args) - len(defs)
        params = [(arg,) if i < fst_def_i else (arg, defs[i - fst_def_i])
                  for i, arg in enumerate(arg_spec.args)]
        return FunctionHelp(name, params, getdoc(callable))


def _parse_argument(raw_argument: str) -> Union[float, str]:
    """Will attempt to parse the argument as a float.
    It will return either a parsed float, or the passed string unchanged"""
    try:
        return float(raw_argument)
    except ValueError:
        return raw_argument


# TODO: Should probably move to a general command helpers file
# FIXME: Currently, Python's type hinting is too primitive to properly annotate Commands of different arities.
#  Unless every command takes the same arguments, it will cause a type error to be raised (TypeVar behavior).
def mapping_from_named_functions(commands) -> CommandMapping:
    """Returns a mapping where the keys are taken from the __name__ attribute of each function."""
    return {command.__name__: command for command in commands}


class CommandShell:
    def __init__(self,
                 command_mapping: dict[str, Command],
                 command_producer: Callable[[], str] = DEFAULT_COMMAND_PRODUCER,
                 result_consumer: Callable[[str], None] = DEFAULT_RESULT_CONSUMER):
        self._commands = command_mapping.copy() | self._produce_shell_commands()
        self._command_producer = command_producer
        self._result_consumer = result_consumer

        self._is_terminating = False

    # def command_loop(self) -> None:
    #     try:
    #         while not self._is_terminating:
    #             raw_command = self._command_producer()
    #             command, *args = raw_command.split()
    #             lower_command = command.lower()
    #             command_func = self._commands.get(lower_command, None)
    #             if command_func is None:
    #                 self._result_consumer(f"Command Not Found: {lower_command}")
    #             else:
    #                 parsed_args = map(_parse_argument, args)
    #                 try:
    #                     result = command_func(*parsed_args)
    #                     if result is not None:
    #                         self._result_consumer(result)
    #                 except Exception as e:
    #                     self._result_consumer(f"Command Error: {e}")
    #     except KeyboardInterrupt:
    #         pass

    def command_loop(self) -> None:
        try:
            last_command = None
            last_args = None
            while not self._is_terminating:
                raw_command = self._command_producer()
                # Figure out what command and args to use
                if raw_command:
                    command, *args = raw_command.split()
                    lower_command = command.lower()
                    command_func = self._commands.get(lower_command, None)
                    parsed_args = [_parse_argument(arg) for arg in args]
                    if command_func is None:
                        self._result_consumer(f"Command Not Found: {lower_command}")
                        continue  # Eww
                elif last_command is not None:
                    command_func = last_command
                    parsed_args = last_args
                else:
                    continue  # No previous command to repeat

                # Then use it
                try:
                    result = command_func(*parsed_args)
                    if result is not None:
                        self._result_consumer(result)
                    last_command = command_func
                    last_args = parsed_args
                except Exception as e:
                    self._result_consumer(f"Command Error: {e}")
        except KeyboardInterrupt:
            pass

    def _show_command_help(self, command: str) -> None:
        command_func = self._commands.get(command, None)
        if command_func is None:
            self._result_consumer(f"Command Not Found {command}")
        else:
            func_help = FunctionHelp.from_callable(command_func)
            self._result_consumer(str(func_help))

    def _show_all_commands(self) -> None:
        self._result_consumer(f"Commands:")
        pre = " " * HELP_PADDING_LENGTH
        for command in self._commands:
            self._result_consumer(f"{pre}{command}")

    def _produce_shell_commands(self) -> CommandMapping:
        def help(command: str = ""):
            """Prints usage information about the given command.
            Lists all available commands if no command is given."""
            if command:
                self._show_command_help(command)
            else:
                self._show_all_commands()

        def exit():
            """Causes the shell to exit. Ctrl+C can be used as well."""
            self._is_terminating = True

        return mapping_from_named_functions([help, exit])

# def multi(iters: int, name: str) -> str:
#     """Multiplies Strings!"""
#     return name * int(iters)
#
# def add(n: int, m: int) -> str:
#     """Adds Numbers!"""
#     return str(n + m)
#
# def greet(name: str) -> str:
#     """Greets You!"""
#     return f"Hello {name}!"
#
#
# test_commands = mapping_from_named_functions([multi, add, greet])

# python -c "import command_shell as cs; s=cs.CommandShell(cs.test_commands);s.command_loop();"