from argparse import ArgumentParser

from report_data import ISEReport


def term_access():
    parser = ArgumentParser(prog='coldClarity')
    cold_args = parser.add_argument_group(title='coldClarity Fields')
    cold_args.add_argument('--config_file', help='location of config file', default= 'config.yaml', type=str)
    args = parser.parse_args()

    c2r = ISEReport(config_file=args.config_file)
    c2r.create_ise_endpoint_report()


if __name__ == '__main__':
    term_access()
