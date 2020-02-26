#!/bin/bash
# Wrapper process to run fail2ban analysis, process and store results, and publish to web server

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

TEMP_DIR=/tmp/fail2ban-analyse
mkdir -p "${TEMP_DIR}"
rm -f "${TEMP_DIR}/"*.{csv,txt,png,js}
cd "${TEMP_DIR}"

# Check if temp dir exists, and we are in it
if [[ ! -d "${TEMP_DIR}" ]] || [[ "${PWD}" != "${TEMP_DIR}" ]] || ! touch testfile.txt 2>/dev/null; then
  echo "WARNING: Cannot create / access / create files in specified temporary directory ${TEMP_DIR} - trying relative path 'tmp/fail2ban-analyse'"
  TEMP_DIR=tmp/fail2ban-analyse
  mkdir -p "${TEMP_DIR}"
  rm -f "${TEMP_DIR}/"*.{csv,txt,png,js}
  cd "${TEMP_DIR}"
  if [[ ! -d "${TEMP_DIR}" ]] || [[ "${PWD}" != "${TEMP_DIR}" ]] || ! touch testfile.txt 2>/dev/null; then
    echo "ERROR:  Cannot create / access / create files in specified temporary directory ${TEMP_DIR} -  check permissions"
    exit 1
  fi
fi

# Config validation - check "${SCRIPT_DIR}/fail2ban_analyse.py" and "${SCRIPT_DIR}/create-attacks-geojson.py" exist, f2b logdir/webdir are both valid dirs
if [[ ! -f "${SCRIPT_DIR}/fail2ban_analyse.py" ]] || [[ ! -f "${SCRIPT_DIR}/create-attacks-geojson.py" ]]; then
  echo "ERROR: cannot locate scripts in specified directory ${SCRIPT_DIR} - check config file"
  exit 1
fi

if [[ ! -d "${OUTPUT_DIR_WEB}" ]] || [[ ! -d "${F2B_LOG_DIR}" ]]; then
  echo "ERROR: You must specify a valid input directory for fail2ban logs and output directory for generated content to publish to webserver - check config file"
  exit 1
fi

if [[ ! -d ${OUTPUT_DIR_HISTORICAL} ]]; then
  echo "WARNING: Specified output directory for archiving full output ${OUTPUT_DIR_HISTORICAL} does not exist, full datestamped output will not be stored"
fi

# Generate list of usernames from failed login attempts - note this is optional, script will function with no username analysis (SSH only)
echo "Attempting to analyse auth/secure logs in ${F2B_LOG_DIR} to determine usernames of failed ssh attempts..."
USERNAME_FILELIST=$(find "${F2B_LOG_DIR}" \( -name "secure*" -o -name "auth*" \) -exec file {} \; | grep text | cut -d: -f1)
# Filelist contains all uncompressed logs from either Debian or Fedora/CentOS systems - note variable unquoted to work with grep
grep ssh ${USERNAME_FILELIST} | sed -n 's/.*invalid user \([^ ]*\).*/\1/p' | grep -v '\\(\[\^' | grep -v '^$' | sort > usernames.txt
if [[ ! -s usernames.txt ]]; then
  echo "WARNING: Could not process system logfiles to find usernames of failed SSH login attempts, username analysis unavailable"
fi

# Run full fail2ban log analyis
echo "-------------------------------------------------------------------------------------------"
"${SCRIPT_DIR}/fail2ban_analyse.py" "${F2B_LOG_DIR}" all

# Check if successful
if [[ $? -ne 0 ]]; then
  echo "ERROR: Fail2ban log analysis failed"
  exit 1
fi
echo "-------------------------------------------------------------------------------------------"

# Move static content to web directory
# NOTE - add any output files that are to be published on web server here - not as well as moving renames from datestamped format to static filename
mv -v *_fail2ban_attacks_per_day_bar.png "${OUTPUT_DIR_WEB}/unauth.png"
mv -v *_fail2ban_country_hist_all.png "${OUTPUT_DIR_WEB}/unauth-country.png"

if [[ -d "${OUTPUT_DIR_HISTORICAL}" ]]; then
  cp *.{csv,txt,png} "${OUTPUT_DIR_HISTORICAL}"
fi

# Prepare CSV input and create GeoJSON
CSV_INPUT=$(find . -name "*fail2ban_attack_IPs_unique.csv" | head -n1)
if [[ ! -s "${CSV_INPUT}" ]]; then
  echo "ERROR: Cannot find CSV file with IP and location info - did fail2ban_analyse.py run correctly?"
  exit 1
fi
echo "-------------------------------------------------------------------------------------------"
"${SCRIPT_DIR}/create-attacks-geojson.py" "${CSV_INPUT}" attacks-geojson.js && mv attacks-geojson.js "${OUTPUT_DIR_WEB}"

# Clean up
rm -f "${TEMP_DIR}/"*.{csv,txt,png,js}

echo "Fail2ban log analysis and visualisation wrapper process completed"
echo "-------------------------------------------------------------------------------------------"
