from base64 import b64encode
from gzip import open as gzopen
from logging.handlers import TimedRotatingFileHandler
from os import path, makedirs, rename, remove, replace,walk
from urllib.parse import quote as url_quote
from io import StringIO
import yaml
from re import sub
from pandas import to_datetime, isna
from datetime import datetime, timedelta

import logging


class Rutils:

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
    def create_file_path(folder: str, file_name: str,parent_dir=None):
        parent_dir = path.dirname(path.abspath(__file__)) if not parent_dir else parent_dir
        file_path = path.join(parent_dir,folder)

        fName = f'{file_path}/{file_name}'
        if not path.exists(f'{file_path}'):
            makedirs(f'{file_path}')

        # move file to correct dir if needed
        if not path.exists(fName):
            try:
                replace(f'{parent_dir}/{file_name}', fName)
            except:
                # file has yet to be created or not in top path
                pass

        return fName

    @staticmethod
    def encode_data(data, base64=True):
        if base64:
            return b64encode(str.encode(data)).decode('utf-8')
        else:
            return url_quote(data, safe='')

    @staticmethod
    def get_yaml_config(config, self_instance):
        if isinstance(config, str):
            with open(config, 'r') as stream:
                try:
                    return yaml.safe_load(stream)
                except yaml.YAMLError as exc:
                    self_instance.logger.info(f'Error processing config file. Error recevied {exc}')

    @staticmethod
    def get_files_from_loc(fold_loc:str,files_to_look_for:list):
        _, _, filenames = next(walk(fold_loc))
        fnames = [names for names in filenames for filames in files_to_look_for if filames in names]
        return fnames

    @staticmethod
    def df_to_string_buffer(df):
        with StringIO() as buffer:
            df.to_csv(buffer,index=False)
            return buffer.getvalue()

    @staticmethod
    def drop_clean_df(df):
        df.drop_duplicates(inplace=True)
        df.dropna(inplace=True)
        df.reset_index(drop=True, inplace=True)
        return df

    def normalize_df(self,df):
        df.columns = df.columns.str.lower()
        df = df.astype(str).apply(lambda x: x.str.lower())
        for col in df.columns:
            if 'mac' or 'calling_station_id' in col:
                df[col] = df[col].apply(self.mac_normalizer)
        return df

    @staticmethod
    def mac_normalizer(df_str):
        clean_mac = sub(r'[^A-Fa-f0-9]', '', df_str)
        if len(clean_mac) == 12:
            return ':'.join(clean_mac[i:i + 2] for i in range(0, 12, 2))
        else:
            return df_str

    @staticmethod
    def qualify_dt_str(dt_object:str):
        potential_dt = to_datetime(dt_object,errors='coerce',format='%d-%m-%Y')
        return potential_dt

    @staticmethod
    def get_last_n_date_from_now(n_date:int) -> tuple:
        today = datetime.now()
        n_date = today - timedelta(days=n_date)
        today = today.strftime('%d-%m-%Y')
        n_date = n_date.strftime('%d-%m-%Y')
        return n_date, today

    def get_time_range(self,time_range,self_instance) -> tuple:
        ep_dt_str, ep_dt_end = None, None
        ep_dt_info = time_range
        if isinstance(ep_dt_info, int):
            # make sure its pos val
            ep_dt_info = abs(ep_dt_info)
            ep_dt_str, ep_dt_end = self.get_last_n_date_from_now(ep_dt_info)
        else:
            # make sure we are only receiving a str val and splice
            ep_dt_info = str(ep_dt_info)
            ep_dt_info = ep_dt_info.split(':')
            if len(ep_dt_info) > 1:
                ep_dt_str = self.qualify_dt_str(ep_dt_info[0])
                ep_dt_end = self.qualify_dt_str(ep_dt_info[1])
                if isna(ep_dt_str) or isna(ep_dt_end):
                    self_instance.logger.critical(f'Time window {ep_dt_info} is not a valid time window! ')
                    return None,None
                else:
                    ep_dt_str = ep_dt_str.strftime('%d-%m-%Y')
                    ep_dt_end = ep_dt_end.strftime('%d-%m-%Y')
        return ep_dt_str, ep_dt_end

def log_collector(log_all=False,file_name='ise_reporting_logs.log'):
    fName = Rutils().create_file_path('logging', file_name)

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
    conHandler.setLevel(logging.INFO)
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
