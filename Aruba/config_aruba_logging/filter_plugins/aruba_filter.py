#!/usr/bin/python
import re

class FilterModule(object):
    def filters(self):
        return {
            'aruba_logging_diff': self.aruba_logging_diff,
            'aruba_negate_firewallcp': self.aruba_negate_firewallcp,
            'aruba_diff': self.aruba_diff
        }


    def aruba_logging_diff(self, logging_stdout, expected_commands):
        # To be used to take logging data from "show run | include 'logging ' " stdout and list of desired commands
        # negate unexpected commands and generate a list of commands to run (negate plus desired based on diff)
        negated_commands = []
        conf_commands = []
        logging_lines = logging_stdout.splitlines()
        # regex pattern for ip address
        ip_regex = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        # Check for lines in running config that are not defined "expected"
        for item in logging_lines:
            if item.rstrip() not in expected_commands and 'logging level' in item:
                negated_commands.append('no ' + item)
            elif item.rstrip() not in expected_commands and ip_regex.search(item):
                negated_commands.append('no logging ' + item.split()[1])
        # Check for lines in "expected" that are not in running config
        for item in expected_commands:
            if item not in logging_lines and item + ' ' not in logging_lines:
                conf_commands.append(item)
        # Return a list of both negated commands and config commands missing
        return negated_commands + conf_commands

    def aruba_negate_firewallcp(self, firewallcp_stdout):
        negated_commands = ["firewall cp"]
        for item in firewallcp_stdout.splitlines():
            if 'any' in item:
                line = item.split()
                ipv = line[0]
                source = line[1]
                proto = line[2]
                start_port = line[3]
                end_port = line[4]
                action = line[5]
                commands = ["no", ipv, action, source, "proto", proto, "ports", start_port, end_port]
                negated_commands.append(" ".join(commands))

            elif 'Permit' in item or 'Deny' in item:
                line = item.split()
                ipv = line[0]
                source = line[1]
                mask = line[2]
                proto = line[3]
                start_port = line[4]
                end_port = line[5]
                action = line[6]
                commands = ["no", ipv, action, source, mask, "proto", proto, "ports", start_port, end_port]
                negated_commands.append(" ".join(commands))

        return negated_commands


    def aruba_diff(self, host_var):
        """
        This function/filter reads the host_var information provided by Ansible aruba_config module to extract "changed lines"
        Example:
        - debug:
            msg: "{{hostvars[inventory_hostname] | aruba_diff }}"
        
        Will provide the changes to be implemented, run with the --diff --check flags to dry run and get information before live updates.
        """
        output_list = []
        for item in host_var:
            if type(host_var[item]) is dict:
                if 'updates' in host_var[item]:
                    if host_var[item]['changed']:
                        update = host_var[item]['updates']
                        for i in range(len(update)):
                            if i > 0:
                                # Add two spaces for child level
                                update[i] = '  ' + update[i]
                        # Add exclaim to end of parent/child
                        update.append('!')
                        output_list += update
        return output_list
