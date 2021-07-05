import os
from pprint import pprint

from .auth import cs_auth
from .aws_handler import get_secret


class Crowdstrike(object):
    
    def __init__(self: str, bucket_name: str) -> None:

        secret = get_secret(bucket_name, 'crowdstrike_auth', 'ap-southeast-2')
        self.falcon = cs_auth(secret['id'], secret['secret'])


    def new_batch_job(self, filter_parameter=None, filter_value=None, hosts_string=None):

        if hosts_string:
            host_list = hosts_string.split(",")
            host_ids = self._hostname_to_id(host_list)
            batch_id = self._init_batch_job(host_ids)
            return batch_id
        else:
            host_list = self._query_devices_by_filter(filter_parameter, filter_value)
            batch_id = self._init_batch_job(host_list)
            return batch_id


    def execute_batch_job(self, base_command, batch_id, command_string):

        PARAMS = {
        'timeout': 30,
        'timeout_duration': '30s'
        }

        BODY = {
            "base_command": base_command,
            "batch_id": batch_id,
            "command_string": f'{base_command} {command_string}',
            "persist_all": True
        }

        response = self.falcon.command('BatchAdminCmd', parameters=PARAMS, body=BODY)

        if not response['body']['errors']:
            print("[+] Successfully executed batch job")
            return response['body']['combined']['resources']
        else:
           print("[-] Could not execute batch job")


    def execute_active_responder_command(self, base_command: str, command_string: str, session_id: str):

        BODY = {
            'base_command': base_command,
            'command_string': f'{base_command} {command_string}',
            'session_id': session_id
        }

        response = self.falcon.command('RTR_ExecuteAdminCommand', body=BODY)

        if response['status_code'] == 201:
            script_result = self.check_active_responder_command(response['body']['resources'][0]['cloud_request_id'])
            return script_result
        else:
            print("[-] Command could not be executed.")
            print(response['body']['errors'])


    def check_active_responder_command(self, cloud_request_id):

        PARAMS = {
            'cloud_request_id': cloud_request_id,
            'sequence_id': 0
        }

        response = self.falcon.command('RTR_CheckAdminCommandStatus', parameters=PARAMS)

        while response['body']['resources'][0]['complete'] == False:
            response = self.falcon.command('RTR_CheckAdminCommandStatus', parameters=PARAMS)
            print('[+] waiting for command to execute...')
        if response['status_code'] == 200:
            return response['body']['resources'][0]['stdout']
        else:
            print("[-] Error while executing command.")
            pprint(response['body']['errors'])


    def _query_devices_by_filter(self, filter_parameter: str, filter_value: str):

        PARAMS = {
        'offset': 0,
        'limit': 100,
        'filter': f"{filter_parameter}: '{filter_value}'"  # manufacturer: dell inc.
        }

        response = self.falcon.command('QueryDevicesByFilter', parameters=PARAMS)

        if response['body']['resources']:
            print(f"[+] Successfully filtering devices using - {filter_parameter}:{filter_value} ")
            return response['body']['resources']
        else:
            print("[-] No hosts could be found, please check the filter expression.")


    def get_device_details_for_batch_job(self, host_id_list):

        response = self.falcon.command('GetDeviceDetails', ids=host_id_list)

        if response['status_code'] == 200:
            hostnames = [host['hostname'] for host in response['body']['resources']]
            return hostnames
        else:
            print("[-] could not get device details...")
            print(response['body']['errors'])
    
        
    def _hostname_to_id(self, hostname_list):

        host_ids = []
        for host in hostname_list:

            PARAMS = {
            'offset': 0,
            'limit': 100,
            'filter': f"hostname:'{host}'"
            }

            response = self.falcon.command('QueryDevicesByFilter', parameters=PARAMS)

            if response['body']['resources']:
                print(f"[+] Successfully added {host} to batch job queue.")
                host_ids.append(response['body']['resources'][0])
            else:
                print(f"[-] {host} could not be found... skipping.")
        return host_ids


    def init_session(self, hostname):

        device_id = self._query_devices_by_filter("hostname", hostname)[0]

        BODY = {
            'device_id': f'{device_id}'
        }

        response = self.falcon.command('RTR-InitSession', body=BODY)
        if response['status_code'] == 201:
            print(f"[+] Session successfully established with {hostname}")
            return response['body']['resources'][0]['session_id']
        else: 
            print("[-] Session could not be established.. Host may be offline")

    
    def _init_batch_job(self, host_list):

        PARAMS = {
        'timeout': 30,
        'timeout_duration': '30s'
        }

        BODY = {
        "host_ids": host_list, 
        }

        response = self.falcon.command('BatchInitSessions', parameters=PARAMS, body=BODY)

        if response['body']['batch_id']:

            successful_host_ids = []
            failed_host_ids = []

            resources = response['body']['resources']
            for item in resources:
                if not resources[item]['complete']:
                    failed_host_ids.append(resources[item]['aid'])
                else:
                    successful_host_ids.append(resources[item]['aid'])

            if failed_host_ids:
                failed_hostnames = self.get_device_details_for_batch_job(failed_host_ids)
                print(f"[-] Failed to initialise Batch session against {len(failed_hostnames)} Hosts")
                print(menu_generator(failed_hostnames))

            if successful_host_ids:
                successful_hostnames = self.get_device_details_for_batch_job(successful_host_ids)
                print(f"[+] Successfully initialised Batch Sessions against {len(successful_hostnames)} Hosts")
                print(menu_generator(successful_hostnames))

            return response['body']['batch_id']
        else:
            print("[-] Couldn't not init batch session... most likely due to no hosts being online.")
            

    def get_device_details(self, hostname):

        IDS = self._query_devices_by_filter("hostname", hostname)

        if IDS:
            response = self.falcon.command('GetDeviceDetails', ids=IDS)
            if response['status_code'] == 200:
                print(f"[+] Successfully retrieved details for {hostname}")
                return response
            else:
                print("[-] could not get device details... Please check hostname")

    
    def device_action(self, hostname, action):

        device_id = self._query_devices_by_filter("hostname", hostname)

        PARAMS = {
            'action_name': f'{action}'
        }

        BODY = {
            "ids": [
            f"{device_id}"
            ]
            }     

        response = self.falcon.command('PerformActionV2', body=BODY, parameters=PARAMS, action_name=f'{action}')
        
        if response['status_code'] == 202:
            return f"[+] {action} successfully performed on {hostname}"
        else:
            print("[-] Failed to run device action. Please check action parameter.")


    def _get_script_ids(self):

        response = self.falcon.command('RTR_ListScripts')

        if response['status_code'] == 200:
            IDS = ','.join(response['body']['resources'])
            return IDS
        else:
            print("[-] Could not retrieve script ids...")


    def get_scripts(self):

        IDS = self._get_script_ids()

        response = self.falcon.command('RTR_GetScripts', ids=IDS)

        if response:
            print("[+] Found Scripts!")
            script_names = [script['name'] for script in response['body']['resources']]
            return script_names


    def deauthenticate(self):
        self.falcon.deauthenticate()
        print("[+] auth token discarded.")


def menu_generator(options):
    return '\n'.join([f'[{str(counter)}] {option}' for counter, option in enumerate(options, 1)])
