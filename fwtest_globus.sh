#!/bin/bash 

# Copyright 2015 University of Chicago
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#Endpoint FW test (Globus side) script v0.02 Dan Powers
#This script checks to make sure an endpoint is allowing all needed
#inbound connections per Globus fw/port documentation
#
#This script requires that the user have an account on each node listed
#under the SERVERS section that is set up for passwordless ssh 
#(key based auth). Script also requires that netcat 'nc' be present on each
#node listed under "#globus server variables" section. Script also requires that the client
#machine that the script is actually run on have nmap installed.

#script options
#set -e
set -u
set -o pipefail
#set -o xtrace

#give usage if no argument passed to script
TEST_EP=$1
if [ "$TEST_EP" = "" ]
then
 echo "Usage:"
 echo "$0 HOSTNAME_OR_IP_ADDRESS_OF_ENDPOINT_TO_BE_TESTED"
 exit 0
fi

#globus server variables
USERNAME=""
CLI_SERVER=""     
BACKEND_SERVER=""

#data test variables
DATA_PORTS="50000-51000"
DATA_PORT_SOME_FAIL="Some ports in the default data port range ($DATA_PORTS) are blocked on $TEST_EP and some are not blocked. This might be OK and it might not be OK. Check with the endpoint admin to make certain that this is intentional. Unless the endpoint has additional ports configured for use outside the default range, they may run into issues where they are more likely to run out of available ports with this configuration."
DATA_PORT_ALL_FAIL="All ports in the default data port range ($DATA_PORTS) on $TEST_EP appear blocked. This is probably a mistake, but might be intentional. Check with endpoint admin to see if they are using a non-default port range here."
DATA_PORT_SUCCESS="All ports in the default data port range ($DATA_PORTS) on $TEST_EP appear to be unblocked. This is what we would expect in a typical install that has its firewall rules properly configured."
DATA_BLOCKED=
DATA_NOT_BLOCKED=

#myproxy test variables
MYPROXY_PORT=7512
MYPROXY_OPEN="Port $MYPROXY_PORT on $TEST_EP is open to "
MYPROXY_NOT_OPEN="MyProxy service not running or port $MYPROXY_PORT on $TEST_EP appears blocked to "
MYPROXY_CHECK=

#gridftp test variables
GRIDFTP_PORT=2811
GRIDFTP_OPEN="Port $GRIDFTP_PORT on $TEST_EP is open to "
GRIDFTP_NOT_OPEN="GridFTP server not running or port $GRIDFTP_PORT on $TEST_EP appears blocked to "
GRIDFTP_CHECK=

#oauth test variables
OAUTH_PORT=443
OAUTH_CLOSED="Port $OAUTH_PORT on $TEST_EP does not appear blocked, but the OAUTH service doesn't appear to be running. This is OK if OAUTH is not in use on this endpoint."
OAUTH_OPEN="Port $OAUTH_PORT is open on $TEST_EP"
OAUTH_BLOCKED="Port $OAUTH_PORT on $TEST_EP appears blocked. This is OK if OAUTH is not in use on this endpoint."
OAUTH_CHECK=

#misc. variables
UNMATCHED_CONDITION="Please report this to Globus Support:"
TEMPFILE="$(mktemp -t globus.temp.XXX)"

###functions###

#clean up after ourselves whenever exiting under a non-SIGKILL condition
function cleanup () {
    rm -f "$TEMPFILE"
}
trap cleanup EXIT

#nmap wrapper
function nmap-scan() {
    local HOST="$1"
    local PORT="$2"
    nmap -Pn -p "$PORT" "$HOST"
}

#verify that $HOST is a resolvable DNS name or valid IP, echo true/false $RESULT to stdout
host-validate() {
    local HOST="$1"
    local RESULT="true"
    ping -W 1 -c 1 "$HOST" &> $TEMPFILE
    PING_CHECK="$(head -1 $TEMPFILE)"
    if [ "$(echo "$PING_CHECK" | grep -o "Unknown host")" = "Unknown host" ]
    then
     RESULT="false"
    fi
    echo $RESULT 
}

#check if myproxy $PORT is open on $HOST from $GLOBUS_SERVER
function myproxy-test() {
    local GLOBUS_SERVER="$1"
    local HOST="$2"
    local PORT="$3"
    ssh "$USERNAME"@"$GLOBUS_SERVER" "echo 'Globus FW Test' | nc -w 10 '$HOST' '$PORT'" > $TEMPFILE
    MYPROXY_CHECK="$(head -1 $TEMPFILE)"
    if [ "$(echo "$MYPROXY_CHECK" | grep -o "VERSION=MYPROXY")" = "VERSION=MYPROXY" ]
    then
     echo $MYPROXY_OPEN $CLI_SERVER
    elif [ "$MYPROXY_CHECK" = "" ]
    then
     echo "$MYPROXY_NOT_OPEN $CLI_SERVER"
    else
     echo $UNMATCHED_CONDITION 
     echo "$MYPROXY_CHECK"
    fi
}

#check if gridftp $PORT is open on $HOST from $GLOBUS_SERVER
function gridftp-test() {
    local GLOBUS_SERVER="$1"
    local HOST="$2"
    local PORT="$3"
    ssh "$USERNAME"@"$GLOBUS_SERVER" "nc -w 10 '$HOST' '$PORT'" > $TEMPFILE
    GRIDFTP_CHECK="$(head -1 $TEMPFILE)"
    if [ "$(echo "$GRIDFTP_CHECK" | grep -o "GridFTP Server")" = "GridFTP Server" ]
    then
     echo $GRIDFTP_OPEN $GLOBUS_SERVER
    elif [ "$GRIDFTP_CHECK" = "" ]
    then
     echo $GRIDFTP_NOT_OPEN $GLOBUS_SERVER
    else
     echo $UNMATCHED_CONDITION 
     echo "$GRIDFTP_CHECK"
    fi
}

#check if oauth $PORT is open on $HOST from workstation
function oauth-test() {
    local HOST="$1"
    local PORT="$2"
    nmap-scan "$HOST" "$PORT" > $TEMPFILE
    OAUTH_CHECK=`grep "$PORT" $TEMPFILE`
    if [ "$(echo "$OAUTH_CHECK" | grep -o "closed")" = "closed" ]
    then
     echo $OAUTH_CLOSED
    elif [ "$(echo "$OAUTH_CHECK" | grep -o "filtered")" = "filtered" ]
    then
     echo $OAUTH_BLOCKED
    elif [ "$(echo "$OAUTH_CHECK" | grep -o "open")" = "open" ]
    then
     echo $OAUTH_OPEN
    else
     echo $UNMATCHED_CONDITION 
     echo "$OAUTH_CHECK"
    fi
}

#check if data $PORTS range is open on $HOST from workstation
data-test() {
    local HOST="$1"
    local PORTS="$2"
    nmap-scan "$HOST" "$PORTS" | tee $TEMPFILE
    DATA_BLOCKED="$(grep -o "filtered" $TEMPFILE | uniq || true)"
    DATA_NOT_BLOCKED="$(grep -o "closed" $TEMPFILE | uniq || true)"
    if [ "$DATA_BLOCKED" != "" ] && [ "$DATA_NOT_BLOCKED" != "" ]
    then
     echo $DATA_PORT_SOME_FAIL
    elif [ "$DATA_BLOCKED" != "" ] && [ "$DATA_NOT_BLOCKED" = "" ]
    then
     echo $DATA_PORT_ALL_FAIL
    elif [ "$DATA_BLOCKED" = "" ] && [ "$DATA_NOT_BLOCKED" != "" ]
    then
     echo $DATA_PORT_SUCCESS
    else
     echo $UNMATCHED_CONDITION
     cat $TEMPFILE
    fi
}

###end functions###

#make sure endpoint argument given is a valid hostname or IP
if [ "$(host-validate "$TEST_EP")" = "false" ]
then
 echo "$TEST_EP is not a valid DNS name or IP address."
 exit 1
fi

#check that endpoint allows inbound on $MYPROXY_PORT from $CLI_SERVER
myproxy-test "$CLI_SERVER" "$TEST_EP" "$MYPROXY_PORT" 

#check that endpoint allows inbound on $GRIDFTP_PORT from $CLI_SERVER
gridftp-test "$CLI_SERVER" "$TEST_EP" "$GRIDFTP_PORT" 

#check that endpoint allows inbound on $GRIDFTP_PORT from $BACKEND_SERVER 
gridftp-test "$BACKEND_SERVER" "$TEST_EP" "$GRIDFTP_PORT"

#check that endpoint allows inbound on $OAUTH_PORT from our local host ($OAUTH_PORT should be open to all)
oauth-test "$TEST_EP" "$OAUTH_PORT"

#check that endpoint allows inbound on $DATA_PORTS from local host ($DATA_PORTS should be open to all)
data-test "$TEST_EP" "$DATA_PORTS" 

