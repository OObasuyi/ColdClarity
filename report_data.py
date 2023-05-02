import csv
import time
from json import loads
from os import path

from tqdm import tqdm

from ise_control import ISE
from messaging import Messaging
from test_control import ISETest, MessagingTest
from utilities import Rutils


class C2CReport:
    def __init__(self, config_file='config.yaml', test: int = 0, test_msg=False):
        self.timestr = time.strftime("%d%b%Y")
        self.top_dir = path.dirname(path.abspath(__file__))
        self.utils = Rutils()

        if test:
            self.ise = ISETest(count_amt=test, config=config_file)
            if test_msg:
                MessagingTest(self.ise.config).send_message('test')
        else:
            self.ise = ISE(config=config_file)

        self.c2c_summary_list = self.ise.config.get('endpoint_buckets_match')
        self.custom_profiles = self.ise.config.get('custom_profiles_match')

    def create_ise_endpoint_report(self, incl_report_type='ep_attributes'):
        # special reports
        if self.ise.config.get('special_reporting').get('use'):
            self.create_special_reporting()
            quit()

        # reg C2C
        fname = self.utils.create_file_path('endpoint_reports', f'{self.ise.config["report"]["Command_name"]}_step{self.ise.phase}_{self.timestr}.csv')
        # pull ep data
        self.ise.retrieve_endpoint_data()
        c2c_eps = self.ise.endpoints.copy()

        if incl_report_type == 'ep_attributes':
            workstation_mac_addrs = c2c_eps.loc[c2c_eps['EndPointPolicy'].str.contains('Workstation')]['MACAddress'].to_list()
            self.create_ise_sw_hw_report(type_='software')
            self.create_ise_sw_hw_report(type_='hardware', hw_mac_list=workstation_mac_addrs)

        # change profile of custom profile to fit report standards if custom list exist
        if self.ise.config.get('custom_profiles_match') is not None:
            custom_profiles_match = self.ise.config.get('custom_profiles_match')
            # fold list of dicts to one list to use in df op
            custom_profiles_match = {k: v for dict_item in custom_profiles_match for k, v in dict_item.items()}
            c2c_eps["EndPointPolicy"].replace(custom_profiles_match, inplace=True)

        with open(fname, 'w+', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([self.ise.config['report']['policy_name'], 'Active'])
            writer.writerow(['C2C Interim Reporting'])
            writer.writerow(['C2C-Reporting Information'])
            writer.writerow(['Owner: ' + self.ise.config['report']['owner']])
            writer.writerow(['Area of Operations: ' + self.ise.config['report']['area_of_operation']])
            writer.writerow([f'Deployment ID:{self.ise.sn}'])
            writer.writerow([f'C2C-Step{self.ise.phase}-2.0-MER-Information'])
            # logical profile summary
            writer.writerow([f'C2C-Step{self.ise.phase}-2.1 {self.ise.config["report"]["prepared_for"]} Device Category', self.ise.endpoints.shape[0]])
            for cat in self.c2c_summary_list:
                logical_group = c2c_eps[c2c_eps['LogicalProfile'] == cat]
                if not logical_group.empty:
                    writer.writerow([cat, logical_group.shape[0]])
                else:
                    writer.writerow([cat, 0])
            # endpoint policy summary
            writer.writerow([f'C2C-Step{self.ise.phase}-2.2 Operating System Summary', self.ise.endpoints.shape[0]])
            grouped_eps = c2c_eps.groupby(by=['EndPointPolicy'])
            grouped_eps_names = list(grouped_eps.groups)
            for gp_name in grouped_eps_names:
                writer.writerow([gp_name, grouped_eps.get_group(gp_name).shape[0]])
            self.ise.logger.info(f'Report Done!. Save file at: {fname}')

        # send email
        if self.ise.config["report"]['send_email']:
            messager = Messaging(self.ise.config)
            messager.send_message(msg_attac_loc_or_buf=fname)

    def create_ise_sw_hw_report(self, type_= 'software', hw_mac_list: list = None):
        # function import until we plop this on the devops server
        import pandas as pd
        fname = self.utils.create_file_path('endpoint_reports', f'{self.ise.config["report"]["Command_name"]}_step{self.ise.phase}_{self.timestr}.csv')
        if type_ == 'software':
            self.ise.logger.info('Collecting Endpoint software infomation from ISE')
            self.ise.get_endpoint_software_info()
            vis = pd.DataFrame(loads(self.ise.sw_catalog.text))
            vis.drop(columns=['id', 'productId'], inplace=True)
        else:
            self.ise.logger.info('Collecting Endpoint hardware infomation from ISE')
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
                    except:
                        pass
                hw_attr_list = [dict(t) for t in {tuple(d.items()) for d in l}]
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
            messager.send_message(msg_attac_loc_or_buf=self.ise.endpoints,attachment_name=self.ise.config['special_reporting']['name_of_file_to_send'])



if __name__ == '__main__':
    c2r = C2CReport()
    # c2r = C2CReport()
    # c2r.create_ise_sw_hw_report('Hardware',['C0-3E-BA-99-3E-29'])
    c2r.create_ise_endpoint_report(incl_report_type='None')
