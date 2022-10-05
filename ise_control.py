import base64
import json

import pandas as pd
import requests

from utilities import rutils, log_collector

requests.packages.urllib3.disable_warnings()


class ISE:
    HEADER_DATA = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:106.0) Gecko/20100101 Firefox/106.0',
    }
    UTILS = rutils()

    def __init__(self, config: str = "config.yaml"):
        self.logger = log_collector()
        self.config = rutils.get_yaml_config(config, self)

        # ISE TACACS username and password
        if self.config['ise']['pipeline']:
            ise_username = self.config['ise']['username']
            ise_password = self.config['ise']['password']
        else:
            ise_username = input("What is your TACACS username? ")
            ise_password = input("What is your TACACS password? ")

        # auth information
        self.ip = self.config['ise']['ip']
        self.user = ise_username
        self.password = ise_password
        self.auth_source = self.config['ise']['auth_source']
        # session information
        self.get_session()
        self.init_ise_session()

        self.phase = self.config['ComplytoConnect']['phase']

    def get_session(self):
        self.logger.debug('Obtaining Session Object')
        self.session = requests.Session()
        self.session.verify = False

    def init_ise_session(self):
        url_csrf = f"https://{self.ip}/admin/JavaScriptServlet"
        url_login = f"https://{self.ip}/admin/LoginAction.do"

        # obtain CSRF token
        token_info = None
        csrf_header = self.HEADER_DATA.copy()
        csrf_header['FETCH-CSRF-TOKEN'] = '1'
        response = self.session.post(url_csrf, headers=csrf_header, data={})
        if response.status_code == 200:
            if 'CSRF' in response.text:
                token_info = response.text.split(':')
                self.csrf_token = {token_info[0]: token_info[1]}

        # get login session
        login_payload = f"username={self.user}" \
                        f"&password={self.password}" \
                        f"&samlLogin=false" \
                        f"&rememberme=on" \
                        f"&name={self.user}" \
                        f"&password={self.password}" \
                        f"&authType={self.auth_source}" \
                        f"&newPassword=" \
                        f"&destinationURL=" \
                        f"&CSRFTokenNameValue={token_info[0]}%{token_info[1]}" \
                        f"&OWASP_CSRFTOKEN={token_info[1]}" \
                        f"&locale=en&" \
                        f"hasSelectedLocale=false"

        login_header = self.HEADER_DATA.copy()
        login_header['Content-Type'] = 'application/x-www-form-urlencoded'
        response = self.session.post(url_login, data=login_payload, headers=login_header, verify=False, allow_redirects=True)
        if response.status_code == 200:
            if 'lastLoginSuccess' in response.text:
                self.HEADER_DATA.update(self.csrf_token)
                self.logger.info('Authentication Successful')
                return True
        self.logger.critical('Authentication Failed, Please Check Configuration and Try Again')

    def get_all_endpoint_data(self):
        endpoints = []
        step_page = 1
        control_size = 500
        while True:
            # step thru endpoint pages
            search_field = f'status=CONTEXT_EXTACT_MATCH_connected' \
                           f'&columns=' \
                           f'&sortBy=MACAddress' \
                           f'&startAt={step_page}' \
                           f'&pageSize={control_size}' \
                           f'&total_pages=5000' \
                           f'&total_entries={control_size}'
            if not bool(self.config.get('only_connected')):
                search_field = search_field.replace('status=CONTEXT_EXTACT_MATCH_connected&', '')

            # change header for search params
            header = self.HEADER_DATA.copy()
            header['_QPH_'] = self.UTILS.encode_data(search_field)

            response = self.session.get(f'https://{self.ip}/admin/rs/uiapi/visibility', headers=header)
            if response.status_code == 200:
                ep_data = response.json()
                if len(ep_data) > 0:
                    endpoints = endpoints + ep_data
                    step_page += 1
                else:
                    break
            else:
                self.logger.critical(f'received HTTP CODE {response.status_code} terminating')
                raise RuntimeError

        # clean list and transform json str to dicts to load into DF
        endpoints = list(set(endpoints))
        endpoints = [json.loads(epd) for epd in endpoints]
        self.logger.warning(f'Gathered {len(endpoints)} endpoints from ISE')
        self.endpoints = pd.DataFrame(endpoints)

    def get_endpoint_data(self, mac_address):
        # Mac addr must be 11:11:11:11:11:11 notation
        response = self.session.get(f'https://{self.ip}/admin/rs/uiapi/visibility/endpoint/{mac_address}', headers=self.HEADER_DATA)
        if response.status_code == 200:
            ep_info = response.json()
            return ep_info
        self.logger.debug(f'Could not receive data for mac address: {mac_address}')

    def get_specific_metadata_from_endpoints(self, specific='LogicalProfile'):
        self.endpoints[specific] = self.endpoints['MACAddress'].apply(lambda x: self.get_endpoint_data(x).get(specific))
        self.endpoints.replace({None: 'unknown'}, inplace=True)

    def get_license_info(self):
        self.logger.warning('Collecting primary node SN')
        header = self.HEADER_DATA.copy()

        license_field = 'command=loadSlConfigDetail&dojo.preventCache=1664971537253'
        header['_QPH_'] = self.UTILS.encode_data(license_field)
        header['Content-Type'] = 'application/x-www-form-urlencoded'

        response = self.session.get(f'https://{self.ip}/admin/licenseAction.do', headers=header)
        if response.status_code == 200:
            license_data = response.json()
            self.logger.warning('Obtained Device Serial Number')
            return license_data['serialNo']
        self.logger.debug(f'Could not obtain primary node SN - Received HTTP status code:{str(response.status_code)}')

    def get_endpoint_software_info(self):
        # applications data
        host_sw = 'pageType=app&columns=productName%2Cversion%2CvendorName%2Ccategories%2CoperatingSystem%2CnoOfDevicesPerApp&sortBy=productName&startAt=1&pageSize=10000'
        # transform to base64 then into the str representation of it
        host_sw = base64.b64encode(str.encode(host_sw)).decode('utf-8')
        # session cookie are persistence so only need to add this header that was implemented from the JS caller
        headers = {'_QPH_': host_sw}
        url = f"https://{self.ip}/admin/rs/uiapi/visibility"
        self.sw_catalog = self.session.get(url, headers=headers)

    def get_endpoint_hardware_info(self, mac_address):
        # can only get data one at a time per mac
        # hardware data
        host_hw = f'columns=NoOfDevicesPerHw%2CMACAddress&sortBy=name&MACAddress={mac_address}&startAt=1&pageSize=10000'
        # transform to base64 then into the str representation of it
        host_hw = base64.b64encode(str.encode(host_hw)).decode('utf-8')
        # session cookie are persistence so only need to add this header that was implemented from the JS caller
        header = self.HEADER_DATA.copy()
        header['_QPH_'] = host_hw
        url = f"https://{self.ip}/admin/rs/uiapi/hwvisibility"
        return self.session.get(url, headers=header)

    def retrieve_endpoint_data(self):
        # deployment ID
        self.sn = self.get_license_info()
        self.endpoint_policies = None
        self.logger.info('Collecting endpoint data, depending on size of database this can take some time')
        self.get_all_endpoint_data()
        self.get_specific_metadata_from_endpoints()
        self.logger.info('Endpoint data collection complete')


if __name__ == '__main__':
    ise = ISE()
    ise.retrieve_endpoint_data()
    # ise.get_endpoint_hardware_info('C0:3E:BA:99:3E:29')
    # print(ise.hw_catalog)
