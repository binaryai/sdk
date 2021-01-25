import os
import json
import platform


def get_user_idadir():
    system = platform.system()
    if system == 'Windows':
        return os.path.join(os.getenv('APPDATA'), "Hex-Rays", "IDA Pro")
    elif system in ['Linux', 'Darwin']:
        return os.path.join(os.getenv('HOME'), ".idapro")
    else:
        return ""


class BinaryAIException(Exception):
    def __init__(self, code, msg, data=None, raw=None):
        super(BinaryAIException, self).__init__(code, msg, data, raw)
        self._code = code
        self._msg = msg
        self._data = data
        self._raw = raw

    @property
    def code(self):
        return self._code

    @property
    def data(self):
        return self._data

    def __str__(self):
        return "{}: {}".format(self._code, self._msg)


class BinaryAILog(object):
    DEBUG = 0
    INFO = 1
    WARN = 2
    ERROR = 3
    level = INFO
    name = "BinaryAI"

    @staticmethod
    def log(level, msg, *args, **kwargs):
        if level >= BinaryAILog.level:
            if args:
                for v in args:
                    msg += str(args)
            if kwargs:
                msg += str(kwargs)

            print("[{}] {}".format(BinaryAILog.name, msg))

    @staticmethod
    def debug(msg, *args, **kwargs):
        BinaryAILog.log(BinaryAILog.DEBUG,
                        msg, *args, **kwargs)

    @staticmethod
    def skip(func_name, reason):
        BinaryAILog.log(BinaryAILog.INFO,
                        "{} is skipped because {}.".format(
                            func_name, reason))

    @staticmethod
    def fail(func_name, reason):
        BinaryAILog.log(BinaryAILog.WARN,
                        "{} failed because {}.".format(
                            func_name, reason))

    @staticmethod
    def success(func_name, func_id, status):
        BinaryAILog.log(BinaryAILog.INFO,
                        "{} successfully {}. ID: {}".format(
                            func_name, status, func_id))

    @staticmethod
    def summary(succ, skip, fail, status):
        BinaryAILog.log(BinaryAILog.INFO,
                        "{} successfully {}, {} skipped, {} failed".format(
                            succ, status, skip, fail))

    @staticmethod
    def fatal(e):
        assert False, "[{}] {}".format(BinaryAILog.name, str(e))


class Config(dict):
    def __init__(self, path, default):
        self.path = path
        if not os.path.exists(path):
            json.dump(default, open(self.path, 'w'), indent=4)
        self.cfg = json.load(open(path))
        for k, v in default.items():
            if not (k in self.cfg and self.cfg[k] is not None):
                self.__setitem__(k, v)

    def __getitem__(self, key):
        return self.cfg[key]

    def __setitem__(self, key, val):
        if key in self.cfg and self.cfg[key] == val:
            return
        self.cfg[key] = val
        json.dump(self.cfg, open(self.path, 'w'), indent=4)


class BinaryAIConfig(Config):
    Default = {
        'token': '',
        'url': 'https://binaryai.tencent.com/api/v3/endpoint',
        'topk': 10,
        'minsize': 5,
        'threshold': 0.90,
    }

    def __init__(self, path, default=None):
        if not os.path.exists(path):
            os.makedirs(path)
        path = os.path.join(path, "binaryai.cfg")
        if default is None:
            default = BinaryAIConfig.Default

        super(BinaryAIConfig, self).__init__(path, default)
