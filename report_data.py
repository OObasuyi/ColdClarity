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

    def create_ise_endpoint_report(self):

        # special reports
        # todo: need to work on SW next then special reporting
        if self.ise.config.get('special_reporting').get('use'):
            self.create_special_reporting()
            quit()

        # reg report
        fname = self.utils.create_file_path('endpoint_reports', f'{self.ise.config["report"]["organization"]}_step{self.ise.step}_{self.timestr}.csv')
        # pull ep data
        self.ise.retrieve_endpoint_data()
        ise_eps = self.ise.endpoints.copy()

        # change profile of custom profile to fit report standards if custom list exist
        if self.ise.config.get('custom_profiles_match') is not None:
            custom_profiles_match = self.ise.config.get('custom_profiles_match')
            # fold list of dicts to one list to use in df op
            custom_profiles_match = {k.lower(): v.lower() for dict_item in custom_profiles_match for k, v in dict_item.items()}
            ise_eps["assigned_policies"].replace(custom_profiles_match, inplace=True)

        with open(fname, 'w+', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([self.ise.config['report']['policy_name'], self.ise.config['report']['policy_name']])
            writer.writerow([f'{self.reporting_name} Interim Reporting'])
            writer.writerow([f'{self.reporting_name}-Reporting Information'])
            writer.writerow(['Owner: ' + self.ise.config['report']['owner']])
            writer.writerow(['Area of Operations: ' + self.ise.config['report']['area_of_operation']])
            writer.writerow([f'Deployment ID:{self.ise.sn}'])
            writer.writerow([f'{self.reporting_name}-Step{self.ise.step}-2.0-MER-Information'])
            # logical profile summary
            if self.ise.step == 1:
                self.ise_step_1(writer, ise_eps)
                pass
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
            logical_group = ise_eps[ise_eps['logical_profile'] == cat.lower()]
            if not logical_group.empty:
                writer.writerow([cat, logical_group.shape[0]])
            else:
                writer.writerow([cat, 0])
        # endpoint policy summary
        writer.writerow([f'{self.reporting_name}-Step{self.ise.step}-2.2 Operating System Summary', self.ise.endpoints.shape[0]])
        grouped_eps = ise_eps.groupby(by=['assigned_policies'])
        grouped_eps_names = list(grouped_eps.groups)
        for gp_name in grouped_eps_names:
            writer.writerow([gp_name, grouped_eps.get_group(gp_name).shape[0]])
        return

    def ise_step_2(self, writer):
        # get Posture conditions
        posture_cons = self.ise.config['step2_conditions_match']
        # check if it exist if so join it to origin
        extended_pos_cons = self.ise.config.get('step2_conditions_custom')
        if extended_pos_cons:
            posture_cons = posture_cons + extended_pos_cons

        common_computing_profiles = 'server|red hat| hel|workstation|OSX'
        # db queries
        get_all_posture_endpoints = "select POLICY,ENDPOINT_ID from posture_assessment_by_condition"
        get_all_auths = "select ORIG_CALLING_STATION_ID,AUTHENTICATION_METHOD,AUTHENTICATION_PROTOCOL,POSTURE_STATUS,ENDPOINT_PROFILE from RADIUS_AUTHENTICATIONS"
        get_all_endpoints ="select B.LOGICAL_PROFILE, B.ASSIGNED_POLICIES, A.MAC_ADDRESS from ENDPOINTS_DATA A, LOGICAL_PROFILES B where A.ENDPOINT_POLICY = B.ASSIGNED_POLICIES"
        get_portal_endpoints ="select MAC_ADDRESS, PORTAL_USER from ENDPOINTS_DATA"

        ep_postured = self.ise.dataconnect_engine(get_all_posture_endpoints)
        ep_auths = self.ise.dataconnect_engine(get_all_auths)
        ep_web = self.ise.dataconnect_engine(get_portal_endpoints)
        ep_all = self.ise.dataconnect_engine(get_all_endpoints)

        ep_active = self.ise.get_all_active_sessions()
        ep_profiled_count = self.ise.get_all_profiler_count()

        if any([ep_postured.empty,ep_active.empty]):
            self.ise.logger.critical(f'No active posture or Posture sessions found!')
            raise ValueError(f'No active posture or Posture sessions found!')

        # normalize
        ep_active = self.utils.normalize_df(ep_active)
        ep_postured = self.utils.normalize_df(ep_postured)
        ep_web = self.utils.normalize_df(ep_web)

        ep_auths = self.utils.drop_clean_df(ep_auths)
        ep_all = self.utils.drop_clean_df(ep_all)
        # conversion needs to happen after the NaNs are dropped
        ep_auths = self.utils.normalize_df(ep_auths)
        ep_all = self.utils.normalize_df(ep_all)
        ep_web = self.utils.normalize_df(ep_web)

        # All endpoints in ISE
        writer.writerow(['Total Discovered Endpoints', ep_all.shape[0]])
        # endpoints that auth'd at some point
        all_macs = ep_all['mac_address'].drop_duplicates().tolist()
        tot_man_ep = ep_auths[ep_auths['orig_calling_station_id'].isin(all_macs)].drop_duplicates(subset='orig_calling_station_id', keep='first')
        writer.writerow(['Total Managed Endpoints', tot_man_ep.shape[0]])
        # device that has been seen via nMAP or whatever that hasnt auth'd
        all_auths = ep_auths['orig_calling_station_id'].drop_duplicates().tolist()
        tot_non_man_ep = ep_all[~ep_all['mac_address'].isin(all_auths)].drop_duplicates(subset='mac_address', keep='first')
        writer.writerow(['Total Non-Managed Endpoints', tot_non_man_ep.shape[0]])
        # devices that can auth via 8021.x
        writer.writerow(['Total 802.1X Endpoints', ep_active[ep_active['user_name'] != ep_active['calling_station_id']].shape[0]])
        # devices that are MAB
        writer.writerow(['Total MAB Endpoints', ep_active[ep_active['user_name'] == ep_active['calling_station_id']].shape[0]])
        # how many profiles we have
        writer.writerow(['Total Profiled Endpoints', ep_profiled_count])
        # if we are doing webauth or some type of auth
        web_list = ep_web['mac_address'][ep_web['portal_user'] != 'none'].tolist()
        other_auth = ep_active[ep_active['calling_station_id'].isin(web_list)]
        writer.writerow(['Total Authenticated Other (SNMP etc)', other_auth.shape[0]])

        # reporting Break
        writer.writerow([])

        auth_ep_list = ep_active['calling_station_id'].drop_duplicates().tolist()
        non_svr_auth_list = ep_all[ep_all['mac_address'].isin(auth_ep_list) & ~ep_all['assigned_policies'].str.contains(common_computing_profiles, regex=True)]
        # how many IoT devices are auth'd
        writer.writerow(['Non-svr/Wkstn Managed Devices', non_svr_auth_list.shape[0]])
        # how many are not
        non_svr_all = ep_all['mac_address'][~ep_all['assigned_policies'].str.contains(common_computing_profiles, regex=True)].drop_duplicates().tolist()
        non_svr_nonauth_list = ep_active[ep_active['calling_station_id'].isin(non_svr_all)]
        writer.writerow(['Non-svr/Wkstn Non-Managed Devices', non_svr_nonauth_list.shape[0]])

        # reporting Break
        writer.writerow([])

        # just all logically profiled Workstation and Servers
        wrk_svr_data = ep_all[ep_all['logical_profile'] == 'workstations and servers'].drop_duplicates(subset='mac_address', keep='first')
        writer.writerow(['Total Workstations and Servers', wrk_svr_data.shape[0]])
        # wrk/svrs not doing auth
        svr_all = ep_all['mac_address'][ep_all['assigned_policies'].str.contains(common_computing_profiles, regex=True)].drop_duplicates().tolist()
        svr_non_auth = ep_active[~ep_active['calling_station_id'].isin(svr_all)]
        writer.writerow(['Unmanaged Workstations and Servers', svr_non_auth.shape[0]])
        # wrk/svrs doing auth
        svr_auth = ep_active[ep_active['calling_station_id'].isin(svr_all)]
        writer.writerow(['Managed Workstations and Servers', svr_auth.shape[0]])

        # reporting Break
        writer.writerow([])

        # Posture compliance
        # todo: make a switch to see what audits conditions are failing
        # get posture status by policy
        grouped_posture_policy = ep_postured.groupby(['policy','endpoint_id'])
        for posture_dicts in posture_cons:
            total_passed = 0
            total_failed = 0
            for report_name,actual_name in posture_dicts.items():
                for policy_name, policy_group in grouped_posture_policy:
                    if actual_name == policy_name[0]:
                        # get all condition results where we passed or failed
                        # get the latest result
                        policy_group.sort_values(by='logged_at', inplace=True,ascending=False)
                        policy_group.drop_duplicates(subset='endpoint_id', keep='first',inplace=True)
                        passed = policy_group[policy_group['policy_status'].str.contains('pass')].shape[0]
                        failed = policy_group[policy_group['policy_status'].str.contains('fail')].shape[0]
                        # added to counters
                        total_passed += passed
                        total_failed += failed
                # write the total hits per policy
                writer.writerow([f'{report_name} Compliant', total_passed])
                writer.writerow([f'{report_name} Non-Compliant', total_failed])

        # collect bios serials and sum
        hw_data = self.ise.get_endpoint_hardware_info()
        hw_data = self.utils.normalize_df(hw_data)
        writer.writerow(['Serial Number Collected', hw_data[hw_data['serialnum'] != 'unknown'].shape[0]])
        self.ise.logger.info("Finished all reports!")
        return

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
