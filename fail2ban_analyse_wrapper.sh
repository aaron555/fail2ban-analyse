#!/bin/bash
# Wrapper process to run fail2ban analysis, process and store results, and publish to web server

# Copyright (C) 2020 Aaron Lockton

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

echo "-------------------------------------------------------------------------------------------"
echo "Fail2ban log analysis and visualisation wrapper process started"

if [[ -s /etc/fail2ban_analyse.conf ]]; then
  source "/etc/fail2ban_analyse.conf"
elif [[ -s config/fail2ban_analyse.conf ]]; then
  source "config/fail2ban_analyse.conf"
else
  echo "ERROR: Cannot find config file at /etc/fail2ban_analyse.conf or config/fail2ban_analyse.conf - please ensure a valid config file is present"
  exit 1
fi

# Config validation - check "${SCRIPT_DIR}/fail2ban_analyse.py" and "${SCRIPT_DIR}/create-attacks-geojson.py" exist, f2b logdir/webdir are both valid dirs (full output dir is optional)
F2B_ABS_PATH=$(readlink -f "${SCRIPT_DIR}/fail2ban_analyse.py")
GEOJ_ABS_PATH=$(readlink -f "${SCRIPT_DIR}/create-attacks-geojson.py")
if [[ ! -f "${F2B_ABS_PATH}" ]] || [[ ! -f "${GEOJ_ABS_PATH}" ]]; then
  echo "ERROR: cannot locate scripts in specified directory ${SCRIPT_DIR} - check config file"
  exit 1
fi

OUTPUT_DIR_WEB_ABS=$(readlink -f "${OUTPUT_DIR_WEB}")
F2B_LOG_DIR_ABS=$(readlink -f "${F2B_LOG_DIR}")
if [[ ! -d "${OUTPUT_DIR_WEB_ABS}" ]] || [[ ! -d "${F2B_LOG_DIR_ABS}" ]]; then
  echo "ERROR: You must specify a valid input directory for fail2ban logs and output directory for generated content to publish to webserver - check config file"
  exit 1
fi

OUTPUT_DIR_HISTORICAL_ABS=$(readlink -f "${OUTPUT_DIR_HISTORICAL}")
if [[ ! -d "${OUTPUT_DIR_HISTORICAL_ABS}" ]]; then
  echo "WARNING: Specified output directory for archiving full output ${OUTPUT_DIR_HISTORICAL} does not exist, full datestamped output will not be stored"
fi

# Set up temporary location and check accessible (must be absolute path - try standard Linux temporary location)
TEMP_DIR_ABS=/tmp/fail2ban-analyse
mkdir -p "${TEMP_DIR_ABS}"
rm -f "${TEMP_DIR_ABS}/"*.{csv,txt,png,js}
pushd "${TEMP_DIR_ABS}" > /dev/null
TESTFILE=testfile_$(date +%s).txt

# Check if temp dir exists, and we are in it
if [[ ! -d "${TEMP_DIR_ABS}" ]] || [[ "${PWD}" != "${TEMP_DIR_ABS}" ]] || ! touch "${TESTFILE}" 2>/dev/null; then
  echo "WARNING: Cannot create / access / create files in default temporary directory ${TEMP_DIR_ABS} - trying relative path 'tmp/fail2ban-analyse'"
  popd > /dev/null
  # If cannot use default location, try relative path instead
  TEMP_DIR=tmp/fail2ban-analyse
  mkdir -p "${TEMP_DIR}"
  rm -f "${TEMP_DIR}/"*.{csv,txt,png,js}
  TEMP_DIR_ABS=$(readlink -f "${TEMP_DIR}")
  pushd "${TEMP_DIR}" > /dev/null
  if [[ ! -d "${TEMP_DIR_ABS}" ]] || [[ "${PWD}" != "${TEMP_DIR_ABS}" ]] || ! touch "${TESTFILE}" 2>/dev/null; then
    echo "ERROR:  Cannot create / access / create files in failover temporary directory ${TEMP_DIR_ABS} -  check permissions or if conflicting file exists"
    exit 1temp
  fi
fi
rm -f "${TESTFILE}"

# Generate list of usernames from failed login attempts - note this is optional, script will function with no username analysis (SSH only)
echo "Attempting to analyse auth/secure logs in ${F2B_LOG_DIR} to determine usernames of failed ssh attempts..."
USERNAME_FILELIST=$(find "${F2B_LOG_DIR_ABS}" -maxdepth 1 \( -name "secure*" -o -name "auth*" \) -exec file {} \; | grep text | cut -d: -f1)
if [[ ! -z ${USERNAME_FILELIST} ]]; then
  # Filelist contains all uncompressed logs from either Debian or Fedora/CentOS systems - note variable unquoted to work with grep
  grep ssh ${USERNAME_FILELIST} | sed -n 's/.*invalid user \([^ ]*\).*/\1/p' | grep -v '\\(\[\^' | grep -v '^$' | sort > usernames.txt
fi
if [[ ! -s usernames.txt ]]; then
  echo "WARNING: Could not process system logfiles to find usernames of failed SSH login attempts, username analysis unavailable"
fi

# Run full fail2ban log analyis - fail2ban_analyse.py
echo "-------------------------------------------------------------------------------------------"
"${F2B_ABS_PATH}" "${F2B_LOG_DIR_ABS}" all

# Check if successful
if [[ $? -ne 0 ]]; then
  echo "ERROR: Fail2ban log analysis failed"
  exit 1
fi
echo "-------------------------------------------------------------------------------------------"

# Move static content to web directory
# NOTE - add any output files that are to be published on web server here - not as well as moving renames from datestamped format to static filename
mv -v *_fail2ban_attacks_per_day_bar.png "${OUTPUT_DIR_WEB_ABS}/unauth.png"
mv -v *_fail2ban_country_hist_all.png "${OUTPUT_DIR_WEB_ABS}/unauth-country.png"

if [[ -d "${OUTPUT_DIR_HISTORICAL_ABS}" ]]; then
  cp *.{csv,txt,png} "${OUTPUT_DIR_HISTORICAL_ABS}"
else
  echo "WARNING: Specified output directory for archiving full output ${OUTPUT_DIR_HISTORICAL} does not exist, only updating main web content"
  echo "Create ${OUTPUT_DIR_HISTORICAL} or change config to store all historical data (PNG,CSV,TXT with no overwriting)"
fi

# Prepare CSV input and create GeoJSON (create-attacks-geojson.py)
CSV_INPUT=$(find . -name "*fail2ban_attack_IPs_unique.csv" | head -n1)
if [[ ! -s "${CSV_INPUT}" ]]; then
  echo "ERROR: Cannot find CSV file with IP and location info - did fail2ban_analyse.py run correctly?"
  exit 1
fi
echo "-------------------------------------------------------------------------------------------"
"${GEOJ_ABS_PATH}" "${CSV_INPUT}" attacks-geojson.js && mv attacks-geojson.js "${OUTPUT_DIR_WEB_ABS}"

# Clean up
rm -f "${TEMP_DIR_ABS}/"*.{csv,txt,png,js}

echo "Fail2ban log analysis and visualisation wrapper process completed"
echo "-------------------------------------------------------------------------------------------"
