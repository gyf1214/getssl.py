
import sys
import os
from typing import TextIO, Any, Dict
from abc import ABCMeta, abstractmethod
import json
from datetime import datetime

StrDict = Dict[str, str]


class LoggerBase(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, fmt: str, *args: Any, **kwds: Any):
        pass


class DummyLogger(LoggerBase):
    def __call__(self, fmt: str, *args: Any, **kwds: Any):
        pass


class DebugLogger(LoggerBase):
    def __init__(self, debug: bool = False, fout: TextIO = sys.stderr):
        self.debug = debug
        self.fout = fout

    def __call__(self, fmt: str, *args: Any, **kwargs: Any):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        frame = sys._getframe(1)
        if self.debug and frame is not None:
            filename = os.path.basename(frame.f_code.co_filename)
            lineno = frame.f_lineno
            fmt = "[{}][{:>16}:{:<5}] {}".format(now, filename, lineno, fmt)
        else:
            fmt = "[{}] {}".format(now, fmt)
        output = fmt.format(*args, **kwargs)
        print(output, file=self.fout, flush=True)


class ConfigBase:
    def __init__(self, path: str, logger: LoggerBase):
        logger("read config path={}", path)
        with open(path, "r") as fin:
            self._raw: StrDict = json.load(fin)


class Actor(metaclass=ABCMeta):
    @abstractmethod
    def run(self): pass
