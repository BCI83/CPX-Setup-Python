#!/bin/bash

cp configure_certs.yml /symphony/symphony-cpx-ansible-role/tasks/
chmod +x profile_addition.sh
cp profile_addition.sh /etc/profile.d/
chmod +x python_setup.py
cp python_setup.py /symphony/
cp setup-config /symphony/