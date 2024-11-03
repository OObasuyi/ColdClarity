# ColdClarity 👁️ 🧊 👁️
[![python](https://img.shields.io/badge/Python-3.9-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org) ![ISE Version](https://img.shields.io/badge/ISE-3.3-blue)

ColdClarity is a tool designed to see data gathered by Cisco ISE from your network. It generates reports based on customized configurations for compliance, device status, and more.

## Table of Contents
- [Features](#Features)
- [Configuration](#Configuration)
- [General Report Settings](#General Report Settings) 
- [Authentication Settings](#Authentication Settings)
- [SMTP Configuration](#SMTP Configuration)
- [Requirements](#Requirements)

## Features

- **Configurable Reporting**: Supports HW/SW cataloging, endpoint profiles, and custom posture policies.
- **Flexible Authentication**: Choose from certificate-based, text-based, and/or ERS-based authentication.
- **Automated Email Notifications**: Sends reports via email to specified recipients.
- **Customizable Profiles and Buckets**: Allows for logical organization of endpoints into profiles and buckets.
- **Specialized Reporting Options**: Option to focus reports on hardware details or other endpoint specifics.

## Configuration

The tool uses `config_templete.yaml` for its settings. Here are some key sections to configure:

### General Report Settings

- **Policy Name**: Define the NAC policy name with `policy_name`.
- **Output Destination**: Set the `destination_filepath` for where the report should be saved.
- **Notification Settings**: Toggle `send_email` to enable email notifications.

### Authentication Settings

- **Certificate-Based**: Set `authentication.cert_based.use` to `True` and provide `cert_pfx_location` and `cert_password`.
- **Text-Based**: Toggle `authentication.text_based.use` and provide `username` and `password` if preferred.
- **ERS-Based**: Uses `ers_based.username` and `ers_based.password`. Please make sure this account has the correct permission in ISE

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
