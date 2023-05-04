#!/bin/bash

##############################################
# aaAPI - FileWave macOS API Command Tool
# Author: Avery Thomas (FileWave)
# Date: 05.22.2019
##############################################

# Log all messages to FileWave Client Log
exec 1>>/var/log/fwcld.log
exec 2>>/var/log/fwcld.log

# Variables from Launch Arguemnts
device_id="$1"
api_token="$2"

# What user in currently logged in? Do NOT change!
logged_in_user=$(stat -f '%Su' /dev/console)

# Determines macOS version
macos_version=$(sw_vers -productVersion | cut -d '.' -f 2)

# Timestamp function for logging
function timestamp {
	echo "$(date +%Y-%m-%d\ %H:%M:%S)|aaAPI|"
}

# Function to call API and return specified data.
function call_api {
PYTHON_ARG="$1" python - << EOF
import os
import json
import urllib2

request = urllib2.Request('https://$filewave_server:20443/inv/api/v1/client/details/$device_id/DesktopClient', headers={'Authorization': '$api_token'})
contents = urllib2.urlopen(request).read()
cf_data = json.loads(contents.decode('utf-8'))

apiString = os.environ['PYTHON_ARG']
apiList = apiString.split(',')

for i in apiList:
    if 'CustomFields__' in i:
        try:
            len(cf_data[i]['value'])
            cf_result = cf_data[i]['value']
            print i
            print '"{}"'.format(cf_result)
        except KeyError:
            print i
            print '"{}"...[NotFound]'.format(i)
        except TypeError:
            print i
            print '"{}"...[NULL]'.format(i)
    else:
        try:
            len(cf_data[i])
            cf_result = cf_data[i]
            print i
            print '"{}"'.format(cf_result)
        except KeyError:
            print i
            print '"{}"...[NotFound]'.format(i)
        except TypeError:
            print i
            print '"{}"...[NULL]'.format(i)
EOF
}

function get_cf {
	custom_fields=$(call_api $1)
	eval "cf_array=($custom_fields)"
	
	# Assign Custom Field internal name as an internal variable.
	count=0
	for cf in "${cf_array[@]}"; do
		if [ $((count%2)) -eq 0 ]; then
    		VAR_NAME="${cf_array[$count]}"
    		VAR_VALUE="${cf_array[$((count+1))]}"
    		printf -v "$VAR_NAME" "$VAR_VALUE"
		fi
		((count++))
	done
}

function update_cf_string {
	if [[ -z "$2" ]];then
		echo "$(timestamp)Setting Custom Field \"$1\" to \"None\"."
	else
		echo "$(timestamp)Setting Custom Field \"$1\" to \"$2\"."
	fi

	curl --silent --output /dev/null -X PATCH https://$filewave_server:20443/inv/api/v1/client/$device_id -H "authorization: $api_token" -H "cache-control: no- cache" -H "content-type: application/json" -d "{\"CustomFields\": {\"$1\":{\"exitCode\":0,\"status\":0,\"updateTime\":\"$(date +%FT%TZ)\",\"value\":\"$2\"}}}"
}

function reset_command {
	echo "$(timestamp)Resetting aaAPI command to \"None\"."
	update_cf_string "aaapi_action" "None"
	echo "$(timestamp)Resetting aaAPI Admin Password."
	update_cf_string "aaapi_secure_token_password" ""
}


function update_users_cf {
	if [[ $macos_version -le 12 ]]; then
		users=$(all_users | tr '\n' ',' | sed 's/.$//')
	elif [[ $macos_version -ge 13 ]]; then
		users=$(secure_token_check "$(all_users)" | tr '\n' ',' | sed 's/.$//')
	fi
	
	update_cf_string "aaapi_user_accounts" "$users"
}

	function all_users {
		all_user_array=( $(dscacheutil -q user | grep "/Users" | awk '{print $2}' | cut -d'/' -f3-) )
		for i in "${all_user_array[@]}"; do
			echo "$i"
		done
}

function secure_token_check {
	for user in $@; do
		secure_token_status=$((sysadminctl -secureTokenStatus "$user") 2>&1)
		
		if [[ $secure_token_status == *"ENABLED"* ]]; then
			echo "$user[SecureTokenEnabled]"
		elif [[ $secure_token_status == *"DISABLED"* ]]; then
			echo "$user[SecureTokenDisabled]"
		fi
	done
}

function logout_user {
	launchctl bootout user/$(id -u "$1")
}

function user_exists {
	if [[ $(dscl . read /Users/"$1" 2>&1) == *"$1"* ]]; then
		echo "true"
	else
		echo "false"
	fi
}

function reset_password {
	echo "$(timestamp)Resetting password for \"$CustomFields__aaapi_account_username\"..."

	if [[ $macos_version -le 9 ]]; then
		reset_method="dscl"
	elif [[ $macos_version -le 12 ]]; then
		reset_method="sysadminctl"
	elif [[ $macos_version -ge 13 ]]; then
		reset_method="sysadminctl_secure"
	fi
	
	if [[ $reset_method == "dscl" ]]; then
		password_changed=$(/usr/bin/dscl . -passwd /Users/"$CustomFields__aaapi_account_username" "$CustomFields__aaapi_account_password" 2>&1)
	elif [[ $reset_method == "sysadminctl" ]]; then
		password_changed=$(sysadminctl -resetPasswordFor "$CustomFields__aaapi_account_username" -newPassword "$CustomFields__aaapi_account_password" 2>&1)
	elif [[ $reset_method == "sysadminctl_secure" ]]; then
		password_changed=$(sysadminctl -adminUser "$CustomFields__aaapi_secure_token_user" -adminPassword "$CustomFields__aaapi_secure_token_password" -resetPasswordFor "$CustomFields__aaapi_account_username" -newPassword "$CustomFields__aaapi_account_password" 2>&1)
	fi

	if [[ $password_changed == *"Done"* ]] && [[ $reset_method == *"sysadminctl"* ]]; then
		update_cf_string "aaapi_status" "[SUCCESS] Password reset for $CustomFields__aaapi_account_username."
		update_cf_string "aaapi_account_username" ""
		update_cf_string "aaapi_account_password" ""
	elif [[ -z $password_changed ]] && [[ $reset_method == "dscl" ]]; then
		update_cf_string "[SUCCESS] aaapi_status" "Password reset for $CustomFields__aaapi_account_username."
		update_cf_string "aaapi_account_username" ""
		update_cf_string "aaapi_account_password" ""
	elif [[ $password_changed == *"Operation is not permitted without secure token unlock."* ]] && [[ $reset_method == "sysadminctl_secure" ]]; then
		update_cf_string "aaapi_status" "[ERROR] Secure Token Admin User not set or is incorrect"
	elif [[ -z $password_changed ]] && [[ $reset_method == *"sysadminctl"* ]] || [[ $password_changed == *"Invalid Path"* ]] && [[ $reset_method == *"dscl"* ]]; then
		update_cf_string "aaapi_status" "[ERROR] $CustomFields__aaapi_account_username user account not found."
	fi	
}

function secure_token_enable {
	if [[ $macos_version -ge 13 ]]; then
		reset_password
	
		secure_token=$(sysadminctl -secureTokenOn "$CustomFields__aaapi_account_username" -password "$CustomFields__aaapi_account_password" -adminUser "$CustomFields__aaapi_secure_token_user" -adminPassword "$CustomFields__aaapi_secure_token_password" 2>&1)
		
		if [[ $secure_token == *"Operation is not permitted without secure token unlock."* ]]; then
			update_cf_string "aaapi_status" "[ERROR] Secure Token not set. Please check or add Admin credentials with Secure Token in Launch Arguments."
		elif [[ $secure_token == *"Done!"* ]]; then
			echo "$(timestamp) Setting \"$CustomFields__aaapi_account_username\" account Secure Token... [OK]"
		fi
	else
		update_cf_string "aaapi_status" "[OK] macOS version 10.$macos_version does not require Secure Tokens."
	fi
}

function create_account {
	echo "$(timestamp) Starting user account creation process...[OK]"
	
	if [[ $CustomFields__aaapi_account_username == *"NULL"* ]]; then
		username="$auth_username"
		password="$CustomFields__aaapi_account_password"
	else
		username="$CustomFields__aaapi_account_username"
		password="$CustomFields__aaapi_account_password"
	fi

	if [[ $(user_exists "$username") == "true" ]]; then
		echo "$(timestamp)User account \"$username\" already exists. Quiting...[OK]"
	else
		echo "$(timestamp)User account \"$username\" NOT found. Creating user account now...[OK]"
		dscl . -create /Users/"$username"
		dscl . -create /Users/"$username" UserShell /bin/bash
		dscl . -create /Users/"$username" RealName "$username"
	
		max_uid=$(dscl . -list /Users UniqueID | awk '{print $2;}' | sort -nr | head -n1)
		echo "$(timestamp) Maximum UniqueID \"$max_uid\". Incrementing by 1...[OK]"
	
		((max_uid++))
	
		echo "$(timestamp)Setting \"$username\" account UniqueID to \"$max_uid\"...[OK]"
		dscl . -create /Users/"$username" UniqueID $max_uid
		dscl . -create /Users/"$username" PrimaryGroupID 20
	
		echo "$(timestamp)Setting \"$username\" account Home Directory to \"/Users/$username\"...[OK]"
		dscl . -create /Users/"$username" NFSHomeDirectory /Users/$username
	
		echo "$(timestamp)Setting \"$username\" account password...[OK]"
		dscl . -passwd /Users/"$username" "$password"
	
		echo "$(timestamp)Adding \"$username\" account to Admin group...[OK]"
		dscl . -append /Groups/admin GroupMembership "$username"

		if [[ $macos_version -ge 13 ]]; then
			secure_token=$(sysadminctl -secureTokenOn "$username" -password "$password" -adminUser "$CustomFields__aaapi_secure_token_user" -adminPassword "$CustomFields__aaapi_secure_token_password" 2>&1)
		
			if [[ $secure_token == *"Operation is not permitted without secure token unlock."* ]]; then
				update_cf_string "aaapi_status" "[ERROR] Secure Token not set. Please check or add Admin credentials with Secure Token in Launch Arguments."
				exit 1
			elif [[ $secure_token == *"Done!"* ]]; then
				echo "$(timestamp)Setting \"$username\" account Secure Token... [OK]"
			fi
		fi
	
		if [ $(user_exists "$username") == "true" ]; then
			update_cf_string "aaapi_status" "User account $username created...[SUCCESS]"
		else
			update_cf_string "aaapi_status" "[ERROR] User account \"$username\" was NOT created and does NOT exist on machine."
		fi
	fi
}

function delete_account {
	for user in $@; do
		logout_user "$user"

		if [[ $macos_version -le 9 ]]; then
			/usr/bin/dscl . -delete "/Users/$user"
			rm -rf "/Users/$user/"
		elif [[ $macos_version -le 12 ]]; then
			delete_account=$(sysadminctl -deleteUser $user -secure 2>&1)
		elif [[ $macos_version -ge 13 ]]; then
			delete_account=$(sysadminctl -deleteUser $user -secure -adminUser "$CustomFields__aaapi_secure_token_user" -adminPassword "$CustomFields__aaapi_secure_token_password" 2>&1)
		fi

		if [[ $macos_version -le 9 ]] && [[ -z $delete_account ]] || [[ $macos_version -ge 10 ]] && [[ $delete_account == *"Deleting record for $user"* ]] ; then
			echo "$(timestamp)User account \"$user\" has been securely deleted...[OK]"
		else
			echo "$(timestamp)Error deleting user account \"$user\"...[ERROR]"
		fi
	done

	if [[ $CustomFields__aaapi_action == "DeleteAllUsersExceptSecureTokenAdmin" ]] && [[ $(all_users) == "$CustomFields__aaapi_secure_token_user" ]]; then
		update_cf_string "aaapi_status" "All user accounts securely deleted except for \"$CustomFields__aaapi_secure_token_user\"...[OK]"
	elif [[ $CustomFields__aaapi_action == "DeleteOneUser" ]] && [[ $(user_exists "$1") == "false" ]]; then
		update_cf_string "aaapi_status" "DeleteOneUser...[SUCCESS]"
	else
		update_cf_string "aaapi_status" "[ERROR] All user accounts except Secure Token User were NOT deleted."
	fi
}

function execute_command {
	remote_command=($1)
	if [[ "$2" == "root" ]]; then
		command_output=$(${remote_command[@]})
		update_cf_string "aaapi_output" "$command_output"
	elif [[ "$2" == "user" ]]; then
		cmd="${remote_command[@]}"
		command_output=$(su - "$logged_in_user" -c "$cmd")
		update_cf_string "aaapi_output" "$command_output"
	fi
}

function teamviewer {
	creds="$1"
	tv_id=${creds%-*}
	tv_pw=${creds#*-}
	su - "$logged_in_user" -c "/Applications/TeamViewer.app/Contents/MacOS/TeamViewer -ac 1 -i $tv_id -P $tv_pw &"
}
	
function send_message {
	alert_title="$1"
	alert_message="$2"
	alert_type="$3"
	alert_icon="/usr/local/sbin/FileWave.app/Contents/Resources/fwGUI.app/Contents/Resources/kiosk.icns"
	
	# Are any users logged in?
	loggedon=$(who | grep console | wc -l)

	if [[ "$loggedon" -lt "1" ]]; then
		update_cf_string "aaapi_status" "No users are logged in. Attemting to resend message in ~120 seconds."
		exit 1
	elif [[ "$alert_type" == "-reply" ]]; then
		notification_timeout="120"
		action_title="Thank you!"
		action_message="Your response has been submitted."

		NOTIFICATION=$(su - "$logged_in_user" -c "/usr/local/bin/alerter -reply -title '$alert_title' -message '$alert_message' -timeout $notification_timeout -appIcon '$alert_icon'")

		case $NOTIFICATION in
			"@TIMEOUT") update_cf_string "aaapi_status" "Message unread due to $notification_timeout second timeout. Resending message in ~120 seconds." && exit 1 ;;
    			"@CLOSED") send_message "$1" "$2" "$3" ;;
    			"@ACTIONCLICKED") send_message "$1" "$2" "$3" ;;
    			"@CONTENTCLICKED") send_message "$1" "$2" "$3" ;;
    			**) update_cf_string "aaapi_output" "From $logged_in_user: $NOTIFICATION" && send_message "$action_title" "$action_message" "-close" "$NOTIFICATION" ;;
		esac
	elif [[ "$alert_type" == "-oneway" ]]; then
		notification_timeout="120"

		NOTIFICATION=$(su - "$logged_in_user" -c "/usr/local/bin/alerter -title '$alert_title' -message '$alert_message' -actions 'Mark as Read' -timeout $notification_timeout -appIcon '$alert_icon'")

		case $NOTIFICATION in
			"@TIMEOUT") update_cf_string "aaapi_status" "Message unread due to $notification_timeout second timeout. Resending message in ~120 seconds." && exit 1 ;;
    			"@CLOSED") send_message "$1" "$2" "$3" ;;
    			"Mark as Read") update_cf_string "aaapi_ouput" "Message read by: $logged_in_user" ;;
    			"@CONTENTCLICKED") send_message "$1" "$2" "$3" ;;
    			**) sleep 1 ;;
		esac		
	elif [[ "$alert_type" == "-close" ]]; then
		notification_timeout="20"
		action_title="Your response:"
		action_message="$4"
		NOTIFICATION=$(su - "$logged_in_user" -c "/usr/local/bin/alerter -title '$alert_title' -message '$alert_message' -actions 'View' -timeout $notification_timeout -appIcon '$alert_icon'")
		
		case $NOTIFICATION in
			"@TIMEOUT") sleep 1 ;;
    			"@CLOSED") sleep 1 ;;
    			"View") send_message "$action_title" "$action_message" "-view" "$action_message" ;;
    			"@CONTENTCLICKED") send_message "$action_title" "$action_message" "-view" "$action_message" ;;
    			**) sleep 1 ;;
		esac
	elif [[ "$alert_type" == "-view" ]]; then
		notification_timeout="20"
		action_title="Message revoked:"
		action_message="Please use your best judgement when submitting responses."
		
		NOTIFICATION=$(su - "$logged_in_user" -c "/usr/local/bin/alerter -title '$alert_title' -message '$alert_message' -actions 'Revoke' -timeout $notification_timeout -appIcon '$alert_icon'")
		
		case $NOTIFICATION in
			"@TIMEOUT") sleep 1 ;;
    			"@CLOSED") sleep 1 ;;
    			"Revoke") send_message "$action_title" "$action_message" "-revoke" "$action_message" ;;
    			"@CONTENTCLICKED") sleep 1 ;;
    			**) sleep 1 ;;
		esac
	elif [[ "$alert_type" == "-revoke" ]]; then
		notification_timeout="20"
		
		update_cf_string "aaapi_output" "From $logged_in_user: [REVOKED BY USER]"
		
		NOTIFICATION=$(su - "$logged_in_user" -c "/usr/local/bin/alerter -title '$alert_title' -message '$alert_message' -actions 'Reply Again' -timeout $notification_timeout -appIcon '$alert_icon'")

		case $NOTIFICATION in
			"@TIMEOUT") update_cf_string "aaapi_status" "Message revoked by user. Resending message in ~120 seconds." && exit 1 ;;
    			"@CLOSED") update_cf_string "aaapi_status" "Message revoked by user. Resending message in ~120 seconds." && exit 1 ;;
    			"Reply Again") send_message "$message_title" "$CustomFields__aaapi_message" "-reply" ;;
    			"@CONTENTCLICKED") update_cf_string "aaapi_status" "Message revoked by user. Resending message in ~120 seconds." && exit 1 ;;
    			**) sleep 1 ;;
		esac
	fi
}


function start_aaAPI {
	filewave_server=$(/usr/libexec/PlistBuddy -c "print :server" "/usr/local/etc/fwcld.plist")
	echo "$(timestamp)Making API call to \"$filewave_server\""

	get_cf "CustomFields__aaapi_action","CustomFields__aaapi_status","CustomFields__aaapi_input","CustomFields__aaapi_output","CustomFields__aaapi_secure_token_user","CustomFields__aaapi_secure_token_password","CustomFields__aaapi_account_username","CustomFields__aaapi_account_password","auth_username"

	echo "$(timestamp)aaAPI command set to \"$CustomFields__aaapi_action\"...[OK]"
	
	if [[ $CustomFields__aaapi_action == "None" ]]; then
		if [[ $authio_status == *"ERROR"* ]]; then
			echo "$(timestamp) [ERROR] found in last status. Check Client Info for more information..."
		else
			update_cf_string "aaapi_status" "[IDLE]"
		fi
	elif [[ $CustomFields__aaapi_action == "SendMessageOneWay" ]]; then
		message_title="Message from Administrator:"
		send_message "$message_title" "$CustomFields__aaapi_input" "-oneway"
		reset_command
	elif [[ $CustomFields__aaapi_action == "SendMessageUserResponse" ]]; then
		message_title="Message from Administrator:"
		send_message "$message_title" "$CustomFields__aaapi_input" "-reply"
		reset_command
	elif [[ $CustomFields__aaapi_action == "TeamViewer" ]]; then
		teamviewer "$CustomFields__aaapi_input"
		reset_command
	elif [[ $CustomFields__aaapi_action == "CreateAccount" ]]; then
		create_account
		reset_command
	elif [[ $CustomFields__aaapi_action == "ResetPassword" ]]; then
		reset_password
		reset_command
	elif [[ $CustomFields__aaapi_action == "DeleteAllUsersExceptSecureTokenAdmin" ]]; then
		delete_account "$(all_users | grep -vw $CustomFields__aaapi_secure_token_user)"
		reset_command
	elif [[ $CustomFields__aaapi_action == "DeleteOneUser" ]]; then
		delete_account "$CustomFields__aaapi_account_username"
		reset_command
	elif [[ $CustomFields__aaapi_action == "EnableSecureToken" ]]; then
		secure_token_enable
		reset_command
	elif [[ $CustomFields__aaapi_action == "ExecuteRootCommand" ]]; then
		reset_command
		execute_command "$CustomFields__aaapi_input" "root"
	elif [[ $CustomFields__aaapi_action == "ExecuteUserCommand" ]]; then
		reset_command
		execute_command "$CustomFields__aaapi_input" "user"
	fi

	echo "$(timestamp)Updating list of current users...[OK]"
	update_users_cf
	echo "$(timestamp)Checking for new commands in ~120 seconds...[OK]"
	
	# Exit 1 to continue Preflight loop
	exit 1
}

start_aaAPI