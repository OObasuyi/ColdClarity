# ColdClarity 👁️ 🧊 👁️
[![python](https://img.shields.io/badge/Python-3.9-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org) ![ISE Version](https://img.shields.io/badge/ISE-3.3-blue)

ColdClarity is a tool designed to see data gathered by Cisco ISE from your network. It generates reports based on customized configurations for compliance, device status, and more.

## Table of Contents
- [Features](#Features)
- [Configuration](#Configuration)
  - [General Report Settings](#General-Report-Settings) 
  - [Authentication Settings](#Authentication-Settings)
  - [Time Range](#Time-Range)
  - [SMTP Configuration](#SMTP-Configuration)
- [Usage](#usage)
  - [Source](#Source)
  - [Containers](#Containers)
- [Troubleshooting](#troubleshooting)

## Features

- **Configurable Reporting**: Supports HW/SW cataloging, endpoint profiles, and custom posture policies.
- **Flexible Authentication**: Choose from certificate-based, text-based, and/or ERS-based authentication.
- **Automated Email Notifications**: Sends reports via email to specified recipients.
- **Customizable Profiles and Buckets**: Allows for logical organization of endpoints into profiles and buckets.
- **Specialized Reporting Options**: Option to focus reports on hardware details or other endpoint specifics.
- **Time Based Options**: if you just want to pull a report on a certain time range or the past number of days.

## Configuration

The tool uses `config_templete.yaml` for its settings which is found at [templates](templates/config_templete.yaml). Here are some key sections to configure:

### General Report Settings

- **Policy Name**: Define the NAC policy name with `policy_name`.
- **Output Destination**: Set the `destination_filepath` for where the report should be saved.
- **Notification Settings**: Toggle `send_email` to enable email notifications.

### Authentication Settings

- **Certificate-Based**: Set `authentication.cert_based.use` to `True` and provide `cert_pfx_location` and `cert_password`.
- **Text-Based**: Toggle `authentication.text_based.use` and provide `username` and `password` if preferred.
- **ERS-Based**: Uses `ers_based.username` and `ers_based.password`. Please make sure this account has the correct permission in ISE


### Time Range
This works well when RAM is limited, and you have many endpoints in ISE, allowing you to retrieve only the most recent information. \
if you only want data for specific time ranges or for the past number of days you can use this:
```yaml
time_window: 15 # in days or a range such as 01-11-2024:06-11-2024
```

### SMTP Configuration

Set up email notifications with:

```yaml
smtp:
  email: your_email@example.com
  server: smtp.example.com
  port: 25
  destination_email: recipient@example.com
  destination_email_cc:
    - cc1@example.com
    - cc2@example.com
```
## usage
### Source
```shell
# make sure you in the ColdClarity Dir. 
# Also if the config YAML is in the current dir or the subdir Config_information you only need to specify the file name 
# otherwise specify the complete PATH 
python3.8 term_access.py --config_file config.yaml
```
### Containers
```shell
# you can use either docker or podman, but the following is created for podman.
# you can also run it natively with out this script as its only if you want to ensure the app runs and exits properly 
# one use-case for this is running this on a cron job in a environment where the app will not work natively
# please edit the BASH file appropriately and give it the correct rights to run
./cold_watcher.bash
```

## troubleshooting
logs are created and placed in the logging directory on run, you can also use a do higher level debuging if you specify it in the `config.yaml` file 

```yaml
# DIAG
test_endpoint_pull: 1 # if you want to get only a certain amount of endpoints back Useful if you want to test with a small portion of endpoints if you have alot
test_messaging_svc: True # if you want to test pulling data without sending a email
debug_console_login: ~ #outputs debug and higher to console
```
