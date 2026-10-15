"""Русское оформление справки; имена команд и коды завершения не меняются."""
import argparse
import sys


def russian_help(text):
    for source, target in {
        'usage:':'Использование:', 'positional arguments:':'Позиционные аргументы:',
        'options:':'Параметры:', 'optional arguments:':'Параметры:',
        'show this help message and exit':'показать справку и завершить работу',
        'the following arguments are required:':'требуются аргументы:',
        'unrecognized arguments:':'неизвестные аргументы:',
        'invalid choice:':'недопустимое значение:', 'choose from':'выберите из',
        'argument ':'аргумент ', 'expected one argument':'ожидается одно значение',
        'not allowed with argument':'несовместим с аргументом',
    }.items():
        text = text.replace(source,target)
    return text


class RussianArgumentParser(argparse.ArgumentParser):
    def format_help(self):
        return russian_help(super().format_help())

    def format_usage(self):
        return russian_help(super().format_usage())

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, f'{self.prog}: ошибка: {russian_help(message)}\n')
