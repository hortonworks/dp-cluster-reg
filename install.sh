#!/bin/bash
#
# HORTONWORKS DATAPLANE SERVICE AND ITS CONSTITUENT SERVICES
# (c) 2016-2018 Hortonworks, Inc. All rights reserved.
# This code is provided to you pursuant to your written agreement with Hortonworks, which may be the terms of the
# Affero General Public License version 3 (AGPLv3), or pursuant to a written agreement with a third party authorized
# to distribute this code.  If you do not have a written agreement with Hortonworks or with an authorized and
# properly licensed third party, you do not have any rights to this code.
# If this code is provided to you under the terms of the AGPLv3:
# (A) HORTONWORKS PROVIDES THIS CODE TO YOU WITHOUT WARRANTIES OF ANY KIND;
# (B) HORTONWORKS DISCLAIMS ANY AND ALL EXPRESS AND IMPLIED WARRANTIES WITH RESPECT TO THIS CODE, INCLUDING BUT NOT
# LIMITED TO IMPLIED WARRANTIES OF TITLE, NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE;
# (C) HORTONWORKS IS NOT LIABLE TO YOU, AND WILL NOT DEFEND, INDEMNIFY, OR HOLD YOU HARMLESS FOR ANY CLAIMS ARISING
# FROM OR RELATED TO THE CODE; AND
# (D) WITH RESPECT TO YOUR EXERCISE OF ANY RIGHTS GRANTED TO YOU FOR THE CODE, HORTONWORKS IS NOT LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, PUNITIVE OR CONSEQUENTIAL DAMAGES INCLUDING, BUT NOT LIMITED TO,
# DAMAGES RELATED TO LOST REVENUE, LOST PROFITS, LOSS OF INCOME, LOSS OF BUSINESS ADVANTAGE OR UNAVAILABILITY,
# OR LOSS OR CORRUPTION OF DATA.
#

SOURCE_TAR_NAME=dp-cluster-reg.tar
TARGET_FOLDER=dp-cluster-reg
if command -v python &>/dev/null
then
    echo "Python  is installed"
else
    echo "Python is not installed"
fi

if [ -z ${SCRIPT_RELEASE+x} ] || [ -z "$SCRIPT_RELEASE" ]
then 
    DOWNLOAD_URL=`curl -s https://api.github.com/repos/hortonworks/dp-cluster-reg/releases/latest |  grep tarball_url | cut -d '"' -f 4`
else
    DOWNLOAD_URL=`curl -s https://api.github.com/repos/hortonworks/dp-cluster-reg/releases/latest | grep ${SCRIPT_RELEASE} | grep tarball_url | cut -d '"' -f 4`
fi

if [ -z "$DOWNLOAD_URL" ]
then
    echo "No valid release found to download.... exiting"
    exit 1
else
    echo "Creating directory ${TARGET_FOLDER}"
    mkdir -p ${TARGET_FOLDER}
    echo "Downloading Release source code using curl"
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


