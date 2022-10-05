from base64 import b64encode
from gzip import open as gzopen
from logging.handlers import TimedRotatingFileHandler
from os import path, makedirs, rename, remove

import yaml

import logging


class rutils:

    def verify_config(self, config):
        return all(self.cfg[config].values())

    def load_config(self, config="config_lab.yml"):
        with open(config, 'r') as stream:
            try:
                self.cfg = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)

    def __init__(self):
        self.cfg = None

    @staticmethod
    def create_file_path(folder: str, file_name: str):
        top_dir = path.dirname(path.abspath(__file__))
        allowed_exts = ['csv', 'log', 'txt']

        input_ext = '.'.join(file_name.split(".")[1:])
        if input_ext not in allowed_exts:
            raise ValueError(f'please ensure you using one of the allowed file types you gave {input_ext}')

        fName = f'{top_dir}/{folder}/{file_name}'
        if not path.exists(f'{top_dir}/{folder}'):
            makedirs(f'{top_dir}/{folder}')
        return fName

    @staticmethod
    def encode_data(data, base64=True):
        if base64:
            return b64encode(str.encode(data)).decode('utf-8')

    @staticmethod
    def get_yaml_config(config, self_instance):
        if isinstance(config, str):
            with open(config, 'r') as stream:
                try:
                    return yaml.safe_load(stream)
                except yaml.YAMLError as exc:
                    self_instance.logger.info(f'Error processing config file. Error recevied {exc}')


def log_collector(log_all=False):
    fName = rutils().create_file_path('logging', 'c2c_reporting_logs.log')

    if not log_all:
        logger = logging.getLogger('ColdClarity')
    else:
        logger = logging.getLogger()
        import http.client as http_client
        http_client.HTTPConnection.debuglevel = 1

    logger.setLevel(logging.DEBUG)
    if logger.hasHandlers():
        logger.handlers = []

    conHandler = logging.StreamHandler()
    conHandler.setLevel(logging.WARN)
    logformatCon = logging.Formatter('%(asctime)s %(levelname)s %(message)s', datefmt='%d-%b-%y %H:%M:%S')
    conHandler.setFormatter(logformatCon)
    logger.addHandler(conHandler)

    fileHandler = TimedRotatingFileHandler(filename=fName, when='midnight', backupCount=90, interval=1)
    fileHandler.setLevel(logging.DEBUG)
    logformatfile = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%d-%b-%y %H:%M:%S')
    fileHandler.setFormatter(logformatfile)
    fileHandler.rotator = GZipRotator()
    logger.addHandler(fileHandler)
    return logger


class GZipRotator:

    def __call__(self, source, dest):
        rename(source, dest)
        f_in = open(dest, 'rb')
        f_out = gzopen("{}.gz".format(dest), 'wb')
        f_out.writelines(f_in)
        f_out.close()
        f_in.close()
        remove(dest)
