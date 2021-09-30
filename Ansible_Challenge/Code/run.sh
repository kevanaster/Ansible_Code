#!/usr/bin/env bash
source /home/python/bin/activate
ansible-playbook pb_configure_network.yml
deactivate
