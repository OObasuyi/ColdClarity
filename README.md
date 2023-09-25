# Cold Clarity

Comply-to-Connect Reporting App for Identity Service Engine (ISE) 


## Table of Contents
- [Running Report](#Running Report)
- [Templates](#Templates)
- [FAQs](#FAQs) 

## Running Report 
### Using Source
```shell
# make sure you in the ColdClarity Dir. 
# Also if the config YAML is in the current dir or the subdir Config_information you only need to specify the file name 
# otherwise specify the complete PATH 
python3.8 term_access.py --config_file config.yaml
```
### Using Containers
```shell
# you can use either docker or podman, but the following is created for podman.
# you can also run it natively with out this script as its only if you want to ensure the app runs and exits properly 
# one use-case for this is running this on a cron job in a enviroment where the app will not work natively
# please edit the BASH file appropriately and give it the correct rights to run
./cold_watcher.bash
```
## Templates
### Generating ISE Certificates for Client Based Auth
If you are using client based authentication for your ISE deployment AND YOU DONT have a client based Cert that ISE has a CA for, 
please look at the `self.signed_cert.bash` in the templates DIR on general instructions on how it works with this APP and ISE
```bash
# running the script is simple please make you give it correct permission
./self.signed_cert.bash
```
### Configuration YAML
1. In the `report` section please fill it out with the information you have and make sure `send_email` is set to `true` 
if you want to send this report automatically with the `prepared_for` specifying the receiver of the report. 
2. In `authentication` specify whether you are using user/password or certificate based login
3. If you are sending this report make sure your specify your mail relay settings.  


## FAQs
**Q**: We have all of our devices in audit mode but our reports are generating that those endpoints are compliant when in ISE under the Failed Conditions 
I see hits for those endpoints. how come? 

**A**: Since ISE treats all audit Policies as Passes, this app will parse the posture Policy _AND NOT_ posture condition to give a more accurate totaling of endpoints status.

**Q**: In the reports my total endpoints and profiled endpoints are not matching my logical profiles buckets

**A**: As of ISE v3.1, it doest support the de-confliction of logical profile assigned to an endpoint. So if you have a 
situation where you have the parent profile and child profile in the same ISE logical profile. ISE will just append the same logical profile to the endpoint. The same case holds true if you also assign the multiple logical profiles to the same endpoint 