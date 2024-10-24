import csv
import time
from json import loads
from os import path
import pandas as pd
from tqdm import tqdm

from ise_control import ISE
from messaging import Messaging
from utilities import Rutils

pd.options.mode.chained_assignment = None


class ISEReport:
    def __init__(self, config_file='config.yaml'):
        self.timestr = time.strftime("%d%b%Y")
        self.top_dir = path.dirname(path.abspath(__file__))
        self.utils = Rutils()

        self.ise = ISE(config=config_file)

        self.ise_summary_list = self.ise.config.get('endpoint_buckets_match')
        self.custom_profiles = self.ise.config.get('custom_profiles_match')
        # get title of the report
        self.reporting_name = self.ise.config["report"]["program name"]

    def create_ise_endpoint_report(self, incl_report_type=None):

        # special reports
        if self.ise.config.get('special_reporting').get('use'):
            self.create_special_reporting()
            quit()

        # reg report
        fname = self.utils.create_file_path('endpoint_reports', f'{self.ise.config["report"]["organization"]}_step{self.ise.step}_{self.timestr}.csv')
        # pull ep data
        self.ise.retrieve_endpoint_data()
        ise_eps = self.ise.endpoints.copy()

        if incl_report_type == 'ep_attributes':
            workstation_mac_addrs = ise_eps.loc[ise_eps['EndPointPolicy'].str.contains('Workstation')]['MACAddress'].to_list()
            self.create_ise_sw_hw_report(type_='software')
            self.create_ise_sw_hw_report(type_='hardware', hw_mac_list=workstation_mac_addrs)

        # change profile of custom profile to fit report standards if custom list exist
        if self.ise.config.get('custom_profiles_match') is not None:
            custom_profiles_match = self.ise.config.get('custom_profiles_match')
            # fold list of dicts to one list to use in df op
            custom_profiles_match = {k: v for dict_item in custom_profiles_match for k, v in dict_item.items()}
            ise_eps["EndPointPolicy"].replace(custom_profiles_match, inplace=True)

        with open(fname, 'w+', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([self.ise.config['report']['policy_name'], 'Active'])
            writer.writerow([f'{self.reporting_name} Interim Reporting'])
            writer.writerow([f'{self.reporting_name}-Reporting Information'])
            writer.writerow(['Owner: ' + self.ise.config['report']['owner']])
            writer.writerow(['Area of Operations: ' + self.ise.config['report']['area_of_operation']])
            writer.writerow([f'Deployment ID:{self.ise.sn}'])
            writer.writerow([f'{self.reporting_name}-Step{self.ise.step}-2.0-MER-Information'])
            # logical profile summary
            if self.ise.step == 1:
                self.ise_step_1(writer, ise_eps)
            elif self.ise.step == 2:
                self.ise_step_2(writer)

            self.ise.logger.info(f'Report Done!. Save file at: {fname}')

        # send email
        if self.ise.config["report"]['send_email']:
            messager = Messaging(self.ise.config)
            messager.send_message(msg_attac_loc_or_buf=fname)

    def ise_step_1(self, writer, ise_eps):
        writer.writerow([f'{self.reporting_name}-Step{self.ise.step}-2.1 {self.ise.config["report"]["prepared_for"]} Device Category', self.ise.endpoints.shape[0]])
        for cat in self.ise_summary_list:
            logical_group = ise_eps[ise_eps['LogicalProfile'] == cat]
            if not logical_group.empty:
                writer.writerow([cat, logical_group.shape[0]])
            else:
                writer.writerow([cat, 0])
        # endpoint policy summary
        writer.writerow([f'{self.reporting_name}-Step{self.ise.step}-2.2 Operating System Summary', self.ise.endpoints.shape[0]])
        grouped_eps = ise_eps.groupby(by=['EndPointPolicy'])
        grouped_eps_names = list(grouped_eps.groups)
        for gp_name in grouped_eps_names:
            writer.writerow([gp_name, grouped_eps.get_group(gp_name).shape[0]])

    def ise_step_2(self, writer):
        # get Posture conditions
        posture_cons = self.ise.config['step2_conditions_match']
        # check if it exist if so join it to origin
        extended_pos_cons = self.ise.config.get('step2_conditions_custom')
        if extended_pos_cons:
            posture_cons = posture_cons + extended_pos_cons

        # normalize df
        step2_data = self.ise.endpoints.copy()

        # get_all_endpoints = "select * from endpoints_data"
        # self.ise.dataconnect_engine(get_all_endpoints)
        step2_data.columns = step2_data.columns.str.lower()
        step2_data = step2_data.apply(lambda x: x.astype(str).str.lower())

        # total active endpoints
        writer.writerow(['Total Discovered Endpoints', step2_data.shape[0]])
        # devices that can posture
        writer.writerow(['Total Managed Endpoints', step2_data[step2_data["devicecompliance"] != 'unknown'].shape[0]])
        # device that cant  posture
        writer.writerow(['Total Non-Managed Endpoints', step2_data[step2_data["devicecompliance"] == 'unknown'].shape[0]])
        # devices that can auth via 8021.x
        writer.writerow(['Total 802.1X Endpoints', step2_data[step2_data["authenticationmethod"].isin(['x509_pki'])].shape[0]])
        # devices that are MAB
        writer.writerow(['Total MAB Endpoints', step2_data[step2_data["authenticationmethod"] == 'lookup'].shape[0]])
        # how many profiles we have
        writer.writerow(['Total Profiled Endpoints', step2_data[step2_data["endpointpolicy"] != 'unknown'].shape[0]])
        # if we are doing webauth or some type of auth???
        writer.writerow(['Total Authenticated Other (SNMP etc)', step2_data[~step2_data["authenticationmethod"].isin(['unknown', 'lookup', 'x509_pki'])].shape[0]])

        # reporting Break
        writer.writerow([])

        # only get user endpoints
        non_svr_ep = step2_data[~step2_data['ad-operating-system'].str.contains('windows server | red hat | rhel', regex=True)]
        # how many user endpoints are reporting posture
        writer.writerow(['Non-svr/Wkstn Managed Devices', non_svr_ep[non_svr_ep["devicecompliance"] != 'unknown'].shape[0]])
        # how many are not
        writer.writerow(['Non-svr/Wkstn Non-Managed Devices', non_svr_ep[non_svr_ep["devicecompliance"] == 'unknown'].shape[0]])

        # reporting Break
        writer.writerow([])

        # just all logically profiled Workstation and Servers
        wrk_svr_data = step2_data[step2_data['logicalprofile'] == 'workstations and servers']
        writer.writerow(['Total Workstations and Servers', wrk_svr_data.shape[0]])
        # wrk/svrs not/are in posture
        writer.writerow(['Unmanaged Workstations and Servers', wrk_svr_data[wrk_svr_data["devicecompliance"] == 'unknown'].shape[0]])
        writer.writerow(['Managed Workstations and Servers', wrk_svr_data[wrk_svr_data["devicecompliance"] != 'unknown'].shape[0]])

        # reporting Break
        writer.writerow([])

        # Posture compliance
        pos_stat = step2_data[step2_data["devicecompliance"] != 'unknown']
        # get posture status by condition
        for match_conditions in posture_cons:
            for k, v in match_conditions.items():
                k, v = k.lower(), v.lower()
                pos_stat[f'{k}_hits'] = pos_stat['posturereport'].apply(lambda x: self.posture_report_spliter(x, v))

        # get all k values from matched conditions for slotting
        matched_keys = [k for match_conditions in posture_cons for k in match_conditions.keys()]
        # write the total hits per condition
        for mk in matched_keys:
            writer.writerow([f'{mk} Compliant', pos_stat[pos_stat[f'{mk}_hits'.lower()] == 'passed'].shape[0]])
            writer.writerow([f'{mk} Non-Compliant', pos_stat[pos_stat[f'{mk}_hits'.lower()] == 'failed'].shape[0]])

        # collect bios serials and sum
        writer.writerow(['Serial Number Collected', step2_data[step2_data['serial number'] != 'unknown'].shape[0]])

    @staticmethod
    def posture_report_spliter(x, get_policy):
        # split by the conditions matched
        posture_report = x.split(',')
        # now split from con name to pass/fail
        for i in posture_report:
            # check if we have a policy match
            if f'{get_policy}\\' in i:
                # parse and return whether this device passed if not return not_applicable
                return i.split(';')[1].strip('\\')
        return 'not_applicable'

    def create_ise_sw_hw_report(self, type_='software', hw_mac_list: list = None):
        # function import until we plop this on the devops server
        fname = self.utils.create_file_path('endpoint_reports', f'{self.ise.config["report"]["organization"]}_step{self.ise.step}_{self.timestr}.csv')
        vis = None
        if type_ == 'software':
            self.ise.logger.info('Collecting Endpoint software information from ISE')
            self.ise.get_endpoint_software_info()
            vis = pd.DataFrame(loads(self.ise.sw_catalog.text))
            vis.drop(columns=['id', 'productId'], inplace=True)
        else:
            self.ise.logger.info('Collecting Endpoint hardware information from ISE')
            hw_count = 0
            hw_attr_list = []
            if hw_mac_list is not None:
                for hw_mac in tqdm(hw_mac_list, total=(len(hw_mac_list)), desc="Getting Hardware info from endpoints", colour='red'):
                    hw_catalog = self.ise.get_endpoint_hardware_info(hw_mac)
                    try:
                        hw_catalog = loads(hw_catalog.text)
                        if len(hw_catalog) < 1:
                            # No Hardware Endpoint Data to report
                            raise ValueError
                        hw_count += 1
                        for hwa in hw_catalog:
                            hw_attr_list.append(hwa)
                    except Exception as error:
                        self.ise.logger.debug(f'CHWR: {error}')
                        pass
                # DONT KNOW WHAT THE FUCK IS THAT
                # hw_attr_list = [dict(t) for t in {tuple(d.items()) for d in l}]
                if len(hw_attr_list) < 1:
                    self.ise.logger.error(f'No {type_} Data to Report')
                    return
                vis = pd.DataFrame(hw_attr_list)
                vis['endpoint_count'] = hw_count
                vis.drop(columns=['vendorId', 'productId'], inplace=True)
        vis.to_csv(fname, index=False)
        self.ise.logger.info(f'Endpoint {type_} Report Done! Saved to: {fname}')
        # send email
        if self.ise.config["report"]['send_email']:
            messager = Messaging(self.ise.config)
            messager.send_message(msg_attac_loc_or_buf=fname)

    def create_special_reporting(self):
        self.ise.special_reporting_data()
        # send email
        if self.ise.config["report"]['send_email']:
            messager = Messaging(self.ise.config)
            messager.send_message(msg_attac_loc_or_buf=self.ise.endpoints, attachment_name=self.ise.config['special_reporting']['name_of_file_to_send'])


if __name__ == '__main__':
    c2r = ISEReport()
    c2r.create_ise_endpoint_report(incl_report_type='None')
