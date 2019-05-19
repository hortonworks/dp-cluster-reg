#!/bin/bash
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

SOURCE_TAR_NAME=dp-cluster-reg.tar
TARGET_FOLDER=dp-cluster-reg
INSTALL_CMCLIENT=${CM:-false}

if command -v python &>/dev/null
then
    echo "Python  is installed"
else
    echo "Python is not installed. Install Python an proceed with installation"
    exit 1
fi

if [ "$CM" = true ]
then
    if [ "$VIRTUAL_ENV" != "" ]
    then
        echo "The script will install cm_client in virtualenv $VIRTUAL_ENV"
    elif [ "$VIRTUAL_ENV" == "" ]
    then
        echo "The script will install  cm_client in global scope"
    fi
    while true; do
        read -p "Do you wish to install cm_client  (y/n)?" choice
        case "$choice" in
            y|Y ) 
            pip install cm_client
            status=$?
            if [ $status -eq 0 ]
            then
                echo "Installation successful"
            else
                echo "Installation of cm_client module required for running the cluster registration script failed. Please install this manually and re-run the script"
                exit $status        
            fi; break;;
            n|N ) exit;;
            * ) echo "Please answer yes or no.";;
        esac
    done
fi

if [ -z ${RELEASE+x} ] || [ -z "$RELEASE" ]
then 
    DOWNLOAD_URL=`curl -s https://api.github.com/repos/hortonworks/dp-cluster-reg/releases/latest |  grep tarball_url | cut -d '"' -f 4`
else
    DOWNLOAD_URL=`curl -s https://api.github.com/repos/hortonworks/dp-cluster-reg/releases | grep ${RELEASE} | grep tarball_url | cut -d '"' -f 4`
fi

if [ -z "$DOWNLOAD_URL" ]
then
    echo "No valid release found to download.... exiting"
    exit 1
else
    echo "Creating directory ${TARGET_FOLDER}"
    mkdir -p ${TARGET_FOLDER}
    echo "Downloading Release source code from ${DOWNLOAD_URL} using curl"
    curl -L -o ${SOURCE_TAR_NAME} ${DOWNLOAD_URL}
    echo "Extracting the archive into ${TARGET_FOLDER}"
    tar -xvzf ${SOURCE_TAR_NAME} -C ${TARGET_FOLDER} --strip-components 1
    UNTAR_STATUS=$?
fi


if [ "x$UNTAR_STATUS" == "x0" ]
then
    echo "Successfully extracted the script in ${TARGET_FOLDER}"
    echo "You can now run"
    echo "cd ${TARGET_FOLDER};python dp-cluster-setup-utility.py"
fi


