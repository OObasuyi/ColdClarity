from argparse import ArgumentParser
from os import path

from report_data import C2CReport


def term_access():
    top_dir = path.dirname(path.abspath(__file__))
    parser = ArgumentParser(prog='coldClarity')
    cold_args = parser.add_argument_group(title='coldClarity Fields')
    cold_args.add_argument('--config_file', help='location of config file', default=path.join(top_dir, 'config.yaml'), type=str)
    cold_args.add_argument('--test_count', help='FOR TESTING ONLY. choose a minimal amount of endpoints to test ', default=20, type=int)
    cold_args.add_argument('--test_msg', help='FOR TESTING ONLY. send a test msg no attachment ', default=False, type=bool)
    args = parser.parse_args()

    c2r = C2CReport(config_file=args.config_file, test=args.test_count, test_msg=args.test_msg)
    c2r.create_ise_endpoint_report(incl_report_type='None')


if __name__ == '__main__':
    term_access()
