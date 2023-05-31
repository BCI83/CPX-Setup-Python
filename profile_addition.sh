## Addition is from here down
if [ -f /symphony/setup-config ]; then
        setup_stage=$(cat /symphony/setup-config | grep -oP '(?<=setup_stage:).*')
        setup_stage="${setup_stage// /}"
        dns1=$(cat /symphony/setup-config | grep -oP '(?<=dns1:).*')
        dns1="${dns1// /}"
        user=$(whoami)
        if [ "$setup_stage" != "complete" ]; then
                if [ "$user" = "root" ]; then
                        cd /symphony/
                        ./python_setup.py
                else
                        if [ "$dns1" = "" ]; then
                                clear
                                echo ""
                                echo "Switching to 'root' user, this may take a minute as DNS is not configured yet"
                                sudo su -
                        else
                                sudo su -
                        fi
                fi
        fi
fi
