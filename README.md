# CPX_Setup

A script to automate the setup of CPXs

Place 'profile_addition.sh' script in '/etc/profile.d/'
Place the 'python_setup.py' script in '/symphony/'
Place the 'setup_config' file in '/symphony/'
(Don't forget to make both scripts executable with 'chmod +x {file}')

The script is then triggered at login/profile load, but only when 'setup_stage: ' does not have a value of 'complete' in the 'setup_config' file
