#!/bin/bash

mv configure_certs.yml /symphony/symphony-cpx-ansible-role/tasks/
chmod +x profile_addition.sh
mv profile_addition.sh /etc/profile.d/
chmod +x python_setup.py
mv python_setup.py /symphony/
mv setup-config /symphony/