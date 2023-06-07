# CPX_Setup

A script to automate the setup of CPXs

place all files on the Cloud Connecteor VM

Make the setup-setup.sh file executable, and run it (this makes the other script files executable and moves them to their correct locations)

The script is then triggered at login/profile load, but only when 'setup_stage: ' does not have a value of 'complete' in the 'setup_config' file
