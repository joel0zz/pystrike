import click
from pprint import pprint

from src.crowdstrike_handler import Crowdstrike 


cs = Crowdstrike("bucket_name")


def menu_generator(options):
    return '\n'.join([f'[{str(counter)}] {option}' for counter, option in enumerate(options, 1)])


@click.group()
def falcon():
    """This is a python CLI tool used to interact with the CS API."""


@click.command(no_args_is_help=True)
@click.option('-h', '--host', help='Hostname of machine to execute script on.')
@click.option('-s', '--script', help='Script to execute against host(s).')
@click.option('-ls', '--list_scripts', help="List RTR scripts available for execution.", is_flag=True)
@click.option('-mh', '--multi_host', help="string of hosts, comma seperated. Script will run against all hosts.")
@click.option('-hf', '--hosts_filter', help="filter paramter: filter value. Eg - manufacturer: dell inc. this will run script against all Dells.")
def runscript(host, script, list_scripts, multi_host, hosts_filter):
    """Run a CrowdStrike RTR script against a single host or multiple hosts."""
    if list_scripts:
        pprint(menu_generator(cs.get_scripts()))
    if host:
        session = cs.init_session(host)
        response = cs.execute_active_responder_command("runscript", f"-CloudFile={script}", session)
        pprint(response)
    if multi_host:
        batch_id = cs.new_batch_job(hosts_string=multi_host)
        response = cs.execute_batch_job("runscript", batch_id, f"-CloudFile={script}")
        pprint(response)
    if hosts_filter:
        query_filter = hosts_filter.split(":")
        batch_id = cs.new_batch_job(filter_parameter=query_filter[0], filter_value=query_filter[1])
        response = cs.execute_batch_job("runscript", batch_id, f"-CloudFile={script}")
        pprint(response)


@click.command(no_args_is_help=True)
@click.option('-h', '--host', help="Retrieve information about a specific host", required=True)
@click.option('-d', '--details', help="Retrieve details about the host", is_flag=True)
@click.option('-a', '--action', type=click.Choice(['contain', 'lift_containment', 'hide_host', 'unhide_host']), help="Actions that can be performed against a host")
def device_action(host, details, action):
    """List Host information or run a device action such as contain"""
    if details:
        pprint(cs.get_device_details(host))
    if action:
        pprint(cs.device_action(host, action))


falcon.add_command(runscript)
falcon.add_command(device_action)
