import base64
import json

import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
from tqdm import tqdm

from utilities import Rutils, log_collector
from requests_pkcs12 import Pkcs12Adapter
from os import getpid
from ssl import create_default_context, CERT_NONE
from xmltodict import parse as xmlparse
import oracledb

requests.packages.urllib3.disable_warnings()


class ISE:
    HEADER_DATA = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:106.0) Gecko/20100101 Firefox/106.0',
    }
    UTILS = Rutils()

    def __init__(self, config: str = "config.yaml"):
        self.logger = log_collector()
        self.logger.info("COLD CLARITY / ISE ENDPOINT REPORTING APP")

        # move config file to new folder
        config = self.UTILS.create_file_path('Config_information', config)
        self.config = self.UTILS.get_yaml_config(config, self)
        # not ideal but meh
        self.logger = log_collector(self.config.get('debug_console_login'))

        # ISE username and password
        if self.config['authentication']['text_based']['use']:
            self.login_type = 'text'
            if self.config['authentication']['pipeline']:
                ise_username = self.config['authentication']['text_based']['username']
                ise_password = self.config['authentication']['text_based']['password']
            else:
                ise_username = input("username: ")
                ise_password = input("password: ")

            # encode cred str to pass as a post msg to ISE
            self.user = self.UTILS.encode_data(ise_username, base64=False)
            self.password = self.UTILS.encode_data(ise_password, base64=False)
            self.auth_source = self.config['authentication']['text_based']['auth_source']
        # cert based
        elif self.config['authentication']['cert_based']['use']:
            self.login_type = 'cert'
            cert_location = self.config['authentication']['cert_based']['cert_pfx_location']
            # move cert to new folder
            self.cert_location = self.UTILS.create_file_path('certificate_information', cert_location)
            self.cert_passwd = self.config['authentication']['cert_based']['cert_password']

        # auth information
        self.ip = self.config['ise']['ip']
        # session information
        self.get_session()
        self.init_ise_session()
        self.step = self.config['EndpointData']['step']
        return

    def get_session(self):
        self.logger.debug('saving ISE Session Object')
        self.session = requests.Session()
        self.session.verify = False
        return

    def init_ise_session(self):
        self.logger.info(f'Initializing ISE Session to {self.ip}')
        url_csrf = f"https://{self.ip}/admin/JavaScriptServlet"
        # obtain CSRF token
        token_info = None
        csrf_header = self.HEADER_DATA.copy()
        csrf_header['FETCH-CSRF-TOKEN'] = '1'
        # Needed FOR USER/PASS AUTH
        if self.login_type == 'text':
            self.session.get(f'https://{self.ip}/admin/', headers=csrf_header)

        response = self.session.post(url_csrf, headers=csrf_header, data={})
        if response.status_code == 200:
            if 'CSRF' in response.text:
                token_info = response.text.split(':')
                self.csrf_token = {token_info[0]: token_info[1]}

        if self.login_type == 'text':
            url_login = f"https://{self.ip}/admin/LoginAction.do"
            login_payload = f"username={self.user}" \
                            f"&password={self.password}" \
                            f"&samlLogin=false" \
                            f"&rememberme=on" \
                            f"&name={self.user}" \
                            f"&password={self.password}" \
                            f"&authType={self.auth_source}" \
                            f"&newPassword=" \
                            f"&destinationURL=" \
                            f"&CSRFTokenNameValue={token_info[0]}%3D{token_info[1]}" \
                            f"&OWASP_CSRFTOKEN={token_info[1]}" \
                            f"&locale=en&" \
                            f"hasSelectedLocale=false" \
                # f"&isPreLoginBannerAccepted=true"
        else:
            url_login = f"https://{self.ip}/admin/"
            login_payload = "preloginbanner=displayed"
            self.session.mount(f"https://{self.ip}", Pkcs12Adapter(pkcs12_filename=self.cert_location, pkcs12_password=self.cert_passwd))

        login_header = self.HEADER_DATA.copy()
        login_header['Referer'] = f'https://{self.ip}admin/'
        login_header['Content-Type'] = 'application/x-www-form-urlencoded'
        response = self.session.post(url_login, data=login_payload, headers=login_header, verify=False, allow_redirects=True)
        if response.status_code == 200:
            if 'lastLoginSuccess' in response.text:
                self.HEADER_DATA.update(self.csrf_token)
                self.logger.debug('CSRF TOKEN Obtained')
                self.logger.info('Authentication Successful')
                return True
        self.logger.critical('Authentication Failed, Please Check Configuration and Try Again')
        quit()

    def ers_mnt_ise_session(self) -> requests.Session:
        self.logger.debug('Obtaining ERS/MNT Session')
        em_session = requests.Session()
        em_session.verify = False
        # it only accepts XML for now >:(
        auth_info = self.config['authentication']
        em_session.headers = {"Accept: application/xml"}
        em_session.auth = HTTPBasicAuth(auth_info['ers_based']['username'], auth_info['ers_based']['password'])
        self.logger.debug('Obtained ERS/MNT Session')
        return em_session

    def logout_ise_session(self):
        self.logger.debug('Logging Out.. Enjoy! :)')
        self.session.get(f'https://{self.ip}/admin/logout.jsp')
        return

    def dataconnect_engine(self,sql_string) -> pd.DataFrame:
        # skip Oracle Server Cert Validation
        db_ssl_context = create_default_context()
        db_ssl_context.check_hostname = False
        db_ssl_context.verify_mode = CERT_NONE
        self.logger.debug('Connecting to ISE DB :)')
        try:
            # connect to DB
            connection = oracledb.connect(
                user='dataconnect',
                password=self.config['dataconnect']['password'],
                host=self.ip,
                service_name='cpm10',
                protocol='tcps',
                port=2484,
                ssl_context=db_ssl_context
            )
            # get info from DB
            cursor = connection.cursor()
            cursor.execute(sql_string)
            columns = [desc[0] for desc in cursor.description]
            output = cursor.fetchall()
            cursor.close()
            connection.close()
        except Exception as execpt_error:
            self.logger.critical(f'error pulling data from Dataconnect: {execpt_error}')
            return pd.DataFrame([])

        try:
            # put in df
            dc_pd = pd.DataFrame(output, columns=columns)
            # clean DB objects from df
            badcols = []
            for x in dc_pd.columns.tolist():
                try:
                    dc_pd[x].astype(str)
                except Exception as error:
                    self.logger.debug(f'error converting column {x} to string {error}')
                    badcols.append(x)
            dc_pd.drop(columns=badcols, inplace=True)
            return dc_pd
        except Exception as execpt_error:
            self.logger.critical(f'error framing data from dataconnect: {execpt_error}')
            return pd.DataFrame([])

    def mnt_data_retrival(self, resource):
        self.logger.debug(f'Obtaining MNT resource "{resource}"')
        mnt_sess = self.ers_mnt_ise_session()
        mnt_result = mnt_sess.get(f'https://{self.ip}/admin/API/mnt/{resource}')
        return mnt_result

    def get_all_active_sessions(self) -> pd.DataFrame:
        self.logger.debug('Obtaining all active sessions')
        galls = self.mnt_data_retrival("Session/ActiveList")
        if galls.status_code == 200:
            data_dict = xmlparse(galls.content)
            df = pd.json_normalize(data_dict['activeList']['activeSession'])
            self.logger.debug(f'{df.shape[0]} Active Sessions Obtained')
            return df
        else:
            self.logger.critical('No active sessions found in results!')
            return pd.DataFrame([])

    def get_all_profiler_count(self):
        self.logger.debug('Obtaining active profile count')
        gapc = self.mnt_data_retrival("Session/ProfilerCount")
        if gapc.status_code == 200:
            data_dict = xmlparse(gapc.content)
            profiler_count = int(data_dict['sessionCount']['count'])
            self.logger.debug('Retrieved profiler count')
            return profiler_count
        self.logger.critical('No active Profiles found in results!')
        return 0

    def get_all_endpoint_data(self):
        get_all_endpoints = "select B.LOGICAL_PROFILE, B.ASSIGNED_POLICIES, A.MAC_ADDRESS from ENDPOINTS_DATA A, LOGICAL_PROFILES B where A.ENDPOINT_POLICY = B.ASSIGNED_POLICIES"
        ep_all = self.dataconnect_engine(get_all_endpoints)

        ep_active = self.get_all_active_sessions()
        if any([ep_active.empty]):
            self.logger.critical(f'No active posture or Posture sessions found!')
            raise ValueError(f'No active posture or Posture sessions found!')

        # normalize
        ep_active = self.UTILS.normalize_df(ep_active)
        ep_all = self.UTILS.drop_clean_df(ep_all)
        # conversion needs to happen after the NaNs are dropped
        ep_all = self.UTILS.normalize_df(ep_all)
        # only get connected
        if bool(self.config.get('only_connected')):
            ep_act_list = ep_active['calling_station_id'].tolist()
            endpoints = ep_all[ep_all['mac_address'].isin(ep_act_list)]
        else:
            endpoints = ep_all

        self.logger.debug(f'Gathered {endpoints.shape[0]} endpoints from ISE')
        self.endpoints = endpoints
        return

    def get_license_info(self):
        self.logger.debug('Collecting MNT SN')
        deployment_data = 'select HOSTNAME,NODE_TYPE,UDI_SN,ACTIVE_STATUS from NODE_LIST'
        node_info = self.dataconnect_engine(deployment_data)
        sn_data = node_info['UDI_SN'][(node_info['ACTIVE_STATUS'] == 'ACTIVE') & (node_info['NODE_TYPE'].str.contains('MNT'))].iloc[0]
        self.logger.debug('Obtained Serial Number')
        return sn_data

    def get_endpoint_software_info(self):
        # applications data
        host_sw = 'pageType=app&columns=productName%2Cversion%2CvendorName%2Ccategories%2CoperatingSystem%2CnoOfDevicesPerApp&sortBy=productName&startAt=1&pageSize=10000'
        # transform to base64 then into the str representation of it
        host_sw = base64.b64encode(str.encode(host_sw)).decode('utf-8')
        # session cookie are persistence so only need to add this header that was implemented from the JS caller
        headers = {'_QPH_': host_sw}
        url = f"https://{self.ip}/admin/rs/uiapi/visibility"
        self.sw_catalog = self.session.get(url, headers=headers)
        return

    def get_endpoint_hardware_info(self) -> pd.DataFrame:
        endpoints = []
        step_page = 1
        control_size = 100

        self.logger.info(f'Getting endpoint hardware info')
        url = f"https://{self.ip}/admin/rs/uiapi/hwvisibility"
        while True:
            # step thru endpoint pages
            header_data = f'pageType=hw&' \
                          f'columns=MACAddress,manufacture,serialNum,noOfAttachments,cpuUsage,memoryUsage,hdUsage,NAS-Port-Id,status,NetworkDeviceName,PhoneID,ip&' \
                          f'sortBy=MACAddress&' \
                          f'startAt={step_page}&' \
                          f'pageSize={control_size}&' \
                          f'total_pages=1&' \
                          f'total_entries={control_size}'

            # transform to base64 then into the str representation of it
            header_data = base64.b64encode(str.encode(header_data)).decode('utf-8')
            # session cookie are persistence so only need to add this header that was implemented from the JS caller
            header = self.HEADER_DATA.copy()
            header['_QPH_'] = header_data
            response = self.session.get(url, headers=header)

            if response.status_code == 200:
                ep_data = response.json()
                if len(ep_data) > 0:
                    endpoints += ep_data
                    step_page += 1
                else:
                    self.logger.critical(f'no HW data for endpoints on page {step_page}')
                    break

        # clean list and transform json str to dicts to load into DF
        endpoints = list(set(endpoints))
        # check if anything in the list
        if len(endpoints) > 0:
            endpoints = [json.loads(epd) for epd in endpoints]
            self.logger.info(f'Gathered {len(endpoints)} endpoints from ISE')
            hw_data = pd.DataFrame(endpoints)
            self.logger.info('Endpoint HW data collection complete')
            return hw_data
        else:
            self.logger.critical(f'no Hardware data gathered from ISE')
            return pd.DataFrame([])

    def special_reporting_data(self):
        special_rep = self.config['special_reporting']
        reporting_location = special_rep.get('reporting_location')
        find_files = special_rep.get('files_to_look_for')
        filter_list = special_rep.get('filter_list')
        special_items = special_rep.get('filter_specifics')
        attr_to_look_for = special_rep.get('get_attribute_from_endpoint')
        fnames = self.UTILS.get_files_from_loc(reporting_location, find_files)
        # df holder
        self.endpoints = pd.DataFrame([])
        for f in fnames:
            ep_df = pd.read_csv(f'{reporting_location}/{f}')
            ep_df = self.filter_data(ep_df, filter_list, special_items)
            self.endpoints = pd.concat([self.endpoints, ep_df], ignore_index=True)
            self.UTILS.create_file_path('archive', f, parent_dir=reporting_location)
        self.get_metadata_from_endpoints(attr_to_look_for)
        self.logger.info('Endpoint special data collection complete')

    def filter_data(self, raw_df: pd.DataFrame, filter_list: list, data_matching: dict = None):
        raw_df.drop(columns=filter_list, inplace=True)
        # if we have specifics we want to match on
        if data_matching:
            for k, v in data_matching.items():
                # try to see if we fit a usecase if not keep going
                try:
                    raw_df = raw_df[raw_df[k].astype(int) > v]
                    continue
                except Exception as error:
                    self.logger.debug(error)

                try:
                    raw_df = raw_df[raw_df[k].str.contains(v)]
                    continue
                except Exception as error:
                    self.logger.debug(error)
        return raw_df

    def retrieve_endpoint_data(self):
        # todo: need to fix with updated code
        # deployment ID
        self.sn = self.get_license_info()
        self.endpoint_policies = None
        self.logger.debug('Collecting endpoint data')
        self.get_all_endpoint_data()
        # pull N or all
        if bool(self.config.get('test_endpoint_pull')):
            self.logger.info(f'Sample Size of {self.config.get("test_endpoint_pull")} Endpoints being used.')
            self.endpoints = self.endpoints.loc[:self.config.get('test_endpoint_pull')]
        return


if __name__ == '__main__':
    ise = ISE()
    ise.retrieve_endpoint_data()
    ise.logout_ise_session()
