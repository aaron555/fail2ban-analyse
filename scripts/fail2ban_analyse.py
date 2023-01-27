#!/usr/bin/env python3

# Analyse log-files produced by fail2ban

# Syntax: ./fail2ban_analyse.py [ <directory> <Number of logs> <Raw attacker info filepath> ]

# All arguments are optional
# If <directory> is not specified default '/var/log/'
# If <number of logs> is not specified default all available (fail2ban.log* in <directory>)
# If <Raw attacker info filepath> is not specified, code looks up info using ipinfo.io (note this takes some time and is limited by ipinfo.io terms of service) and creates and saves raw attacker info file. Set to "nolookup" to disable geolocation and simply analyse attacker IPs only
# Log naming convention - fail2ban.log; fail2ban.log.1; fail2ban.log.2.gz; etc (Debian based) or fail2ban.log; fail2ban.log-YYYYMMDD; fail2ban.log-YYYYMMDD.gz; etc (Fedora/RHEL/CentOS)
# IMPORTANT - log file directory must not contain any files of the form fail2ban.log* which are not valid logs!

# Note - if username analysis is also required, you must create a file 'usernames.txt' in the same directory as this script, using the following command, before running this script:
# sudo grep ssh ${USERNAME_FILELIST} | sed -n 's/.*invalid user \([^ ]*\).*/\1/p' | grep -v '\\(\[\^' | grep -v '^$' | sort > usernames.txt
# Where ${USERNAME_FILELIST} is a list of file(s) containing all available uncompressed logs with with ssh login info (typically /var/log/auth.log* in Debian and /var/log/secure* in CentOS/Debian)

# Example calls:
# fail2ban_analyse.py /var/log all nolookup
# fail2ban_analyse.py /home/user 5 20000101_fail2ban_raw_attacker_info.txt

# Outputs datestamped files in the same directory in which the code is located containing all raw log data (YYYYMMDD_fail2ban_all_raw_logs.txt), CSVs with all IPs, unique IPs and unique subnets, and raw attacker info (if not specified), and plots in PNG format

# Changelog
# 12/01/2015 - First full version outputting CSV and PNG results
# 25/01/2015 - Added compatibility with Fedora logs
# 20/02/2020 - Converted to python3 (explicitly convert inputs from files to text and dict objects to lists)
# 09/03/2020 - Bug fix for logs with less than 3 unique IPs, subnets or countries

# Copyright (C) 2015, 2020 Aaron Lockton

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

import gzip
import sys
import os
import glob
import subprocess
from time import sleep, gmtime, strftime
import time
from collections import Counter

print (strftime("%Y-%m-%d_%H:%M:%S: Starting fail2ban log analysis", gmtime()))
start_time=time.time()

# Process arguments and set defaults
if len(sys.argv) < 2:
  logdir = "/var/log/"
else:
  logdir = sys.argv[1]
  temp, lastchar = logdir[:-1], logdir[-1]
  if lastchar != "/":
    logdir = logdir + "/"
  if os.path.isdir(logdir) != 1:
    print("WARNING: Invalid path '%s' specified - using default" % logdir)
    logdir = "/var/log/"

available_logs = len(glob.glob(logdir + "fail2ban.log*"))
if len(sys.argv) > 2 and str.isdigit(sys.argv[2]):
  numlogs = int(sys.argv[2])
  if numlogs > available_logs:
    print("WARNING: only %d logs of the specified form found" % available_logs)
    numlogs = available_logs
else:
  numlogs = available_logs

if numlogs == 0:
  print("ERROR: No logs found - Exiting")
  sys.exit(1)

print("Using %d log files in %s" % (numlogs, logdir))


# Obtain list of logs on disk
log_list = glob.glob(logdir + "fail2ban.log*")
log_list.sort()
#print(log_list)

# Determine if logs are Debian or Fedora, re-order accordingly
if numlogs > 1:
  test_name = log_list[1]
  #print(test_name)
  if test_name[-2:] == "gz":
    test_name = test_name.rsplit(".",1)[0]
  if str.isdigit(test_name.split(".")[-1]):
    # Debian logs with .1, .2, .3 etc
    debian = 1
    print("Using Debian log rotation system")
  elif str.isdigit(test_name.split("-")[-1]):
    # Fedora logs with -yyyymmdd
    debian = 0
    print("Using Fedora log rotation system")
    log_list =  log_list[1:] + log_list[:1]
    log_list.reverse()
  else:
    print("ERROR: unrecognised logfile %s - only standard Debian and Fedora rotated logs can be processed - Exiting" % log_list[1])
    sys.exit(1)
  #print(log_list)

# Open, uncompress and combine logs
raw_log = ""
for ii in range(0, numlogs):
  print("Opening log file %s" % log_list[ii])
  try:
    if log_list[ii].split(".")[-1] == "gz":
      # print("gzip")
      f = gzip.open(log_list[ii], "rt")
    else:
      f = open(log_list[ii])
    raw_log = f.read() + raw_log
    f.close()
  except:
    print("WARNING: Cannot open log file %s - check permissions?" % log_list[ii])

# Check if any log lines were read successfully
if len(raw_log) == 0:
  print("ERROR: No log lines could be read - Exiting")
  sys.exit(1)


# Write file with all raw logs (yyyymmdd_fail2ban_all_raw_logs.txt)
filename_stub = strftime("%Y%m%d_fail2ban", gmtime())
raw_log_filename = filename_stub+"_all_raw_logs.txt"
print("Writing raw logs to %s" % raw_log_filename)
f = open(raw_log_filename, "w")
f.write(raw_log)
f.close

# Find all banned IPs
raw_log = raw_log.splitlines()
print ("Analysing %d total lines in log" % len(raw_log))
IP = []
datestamp =[]
for ii in range(0, len(raw_log)):
  log_line = raw_log[ii]
  if "Ban " in log_line:
    IP_loc = log_line.find("Ban ")
    IP_extract = log_line[IP_loc+4:].split(" ", 1)[0]
    IP.append(IP_extract)
    datestamp.append(log_line[0:19])
# Check if log contains any valid timestamps
if len(datestamp) == 0:
  print("WARNING: No banned IPs found in supplied logfile(s) - either logfile(s) not recognised fail2ban log format, or no IPs were banned during the analysis period - exiting...")
  # Note this is not necessarily an error - could be simply no banned IPs in analysis period
  sys.exit(0)
# Write log all all banned IPs with timestamps (yyyymmdd_fail2ban_attack_IPs_all.csv - no geolocatiom)
print("Log covers attacks from %s to %s" % (datestamp[0], datestamp[-1]))
IP_log_filename = filename_stub+"_attack_IPs_all.csv"
print("Writing log of all attack IPs with timestamps to %s" % IP_log_filename)
f = open(IP_log_filename, "w")
f.write("Timestamp,IP address\n")
counter = 0
for line in IP:
  f.write("%s,%s\n" % (datestamp[counter], line))
  counter+= 1
f.close

# Find all unique banned IPs
IP_unique = set(IP)
IP_unique = list(IP_unique)
IP_unique.sort()
print("Total %d attacks from %d unique IPs" % (len(IP), len(IP_unique)))
IP_unique_filename = filename_stub+"_attack_IPs_unique.csv"
# Identify top 3 worst offending IPs
num_attacks =[]
for line in IP_unique:
  num_attacks.append(IP.count(line))
sort_indices = sorted(range(len(num_attacks)), key=lambda k: num_attacks[k])
worst_IPs = ("1-%s (%s)" % (IP_unique[sort_indices[-1]], num_attacks[sort_indices[-1]]))
if len(sort_indices) >= 2:
  worst_IPs += ("; 2-%s (%s)" % (IP_unique[sort_indices[-2]], num_attacks[sort_indices[-2]]))
if len(sort_indices) >= 3:
  worst_IPs += ("; 3-%s (%s)" % (IP_unique[sort_indices[-3]], num_attacks[sort_indices[-3]]))
print("Top 3 offenders: " +worst_IPs)
# Write unique banned IPs to log (yyyymmdd_fail2ban_attack_IPs_unique.csv - no geolocation)
print("Writing log of all UNIQUE attack IPs to %s" % IP_unique_filename)
f = open(IP_unique_filename, "w")
f.write("IP address,Number of Attacks\n")
counter = 0
for line in IP_unique:
  f.write("%s,%s\n" % (line, num_attacks[counter]))
  counter+= 1
  f.close

# Find all banned IPs with unique subnet (/24)
IP_unique_subnet = []
for line in IP_unique:
  line_subnet = line.rsplit(".",1)[0] + "."
  if not any(line_subnet in s for s in IP_unique_subnet):
    IP_unique_subnet.append(line)
IP_unique_subnet.sort()
print("These attacks come from %d unique subnets (/24)" % len(IP_unique_subnet))
# Find top 3 worst offending subnets
IP_trim = []
for line in IP:
  IP_trim.append(line.rsplit(".",1)[0] + ".")
num_attacks_subnet = []
for line in IP_unique_subnet:
  num_attacks_subnet.append(IP_trim.count(line.rsplit(".",1)[0] + "."))
sort_indices_subnet = sorted(range(len(num_attacks_subnet)), key=lambda k: num_attacks_subnet[k])
worst_subnets =  ("1-%s.x (%s)" % (IP_unique_subnet[sort_indices_subnet[-1]].rsplit(".",1)[0], num_attacks_subnet[sort_indices_subnet[-1]]))
if len(sort_indices_subnet) >= 2:
  worst_subnets += ("; 2-%s.x (%s)" % (IP_unique_subnet[sort_indices_subnet[-2]].rsplit(".",1)[0], num_attacks_subnet[sort_indices_subnet[-2]]))
if len(sort_indices_subnet) >= 3:
  worst_subnets += ("; 3-%s.x (%s)" % (IP_unique_subnet[sort_indices_subnet[-3]].rsplit(".",1)[0], num_attacks_subnet[sort_indices_subnet[-3]]))
print("Top 3 subnets (/24): " + worst_subnets)
# Save logs of unique-subnet data (yyyymmdd_fail2ban_attack_IPs_unique_subnet.csv - no geolocation)
IP_subnet_filename = filename_stub+"_attack_IPs_unique_subnet.csv"
print("Writing log of all UNIQUE SUBNETS (assume /24) to %s" % IP_subnet_filename)
f = open(IP_subnet_filename, "w")
f.write("Subnet (/24),Number of Attacks\n")
counter = 0
for line in IP_unique_subnet:
  f.write("%s,%s\n" % (line.rsplit(".",1)[0]+".0", num_attacks_subnet[counter]))
  counter+= 1
f.close

# If username list is available, process to add to plot
if os.path.isfile("usernames.txt"):
  print("Reading invalid usernames from usernames.txt file...")
  with open("usernames.txt", "r") as f:
    userlist = f.read().splitlines()
    rankedusers = Counter(userlist)
    usertext = "Top users: "
    for user,count in rankedusers.most_common(6):
      usertext += '%s (%d), ' % (user, count)
  print(usertext)
else:
  print("WARNING: usernames.txt file not found - no username analysis possible")
  usertext=""

# Write summary file up to available data
summary_filename = filename_stub+"_log_analysis_summary.txt"
print("Writing summary log %s" % summary_filename)
with open(summary_filename, "w") as f:
  f.write(strftime("FAIL2BAN log analysis carried out on %Y-%m-%d\n\n", gmtime()))
  f.write("Log files processed: %s\n" % numlogs)
  f.write("Total Attacks: %s\n" % len(IP))
  f.write("Unique IPs: %s\n" % len(IP_unique))
  f.write("Unique Subnets (/24): %s\n" % len(IP_unique_subnet))
  f.write("First Attack: " + datestamp[0] + "\n")
  f.write("Last Attack: " + datestamp[-1] + "\n\n")
  f.write("Top 3 offenders (IP): " +worst_IPs + "\n")
  f.write("Top 3 subnets (/24): " + worst_subnets+ "\n")
  f.write(usertext + "\n")

usertext = "\n" + usertext

# Calculate and plot Bar chart of number of attacks per day
print("Importing modules and plotting number of attacks per day on chart")
from matplotlib.dates import date2num, DAILY
import datetime as DT
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
datenums = []
num_attacks_day = []
total_today = 0
prev_day = date2num(DT.datetime.strptime(datestamp[0][0:10], "%Y-%m-%d"))
for ele in datestamp:
  line_day = date2num(DT.datetime.strptime(ele[0:10], "%Y-%m-%d"))
  if line_day == prev_day:
    total_today += 1
  else:
    datenums.append(prev_day)
    num_attacks_day.append(total_today)
    total_today = 1
    prev_day = line_day
datenums.append(prev_day)
num_attacks_day.append(total_today)
# Plot bar chart (yyyymmdd_fail2ban_attacks_per_day_bar.png)
fig, ax = plt.subplots(1)
plt.bar(datenums, num_attacks_day)
ax.xaxis_date()
loc = ax.xaxis.get_major_locator()
loc.maxticks[DAILY] = 12
plt.ylabel('Number of attacks')
plt.rcParams["axes.titlesize"] = 10
plt.title("Total %d attacks from %d unique IPs\n%s\n%s%s" % \
  (len(IP), len(IP_unique), worst_IPs, worst_subnets, usertext))
fig.subplots_adjust(top=0.85)
fig = matplotlib.pyplot.gcf()
fig.set_size_inches(8,6)
fig.autofmt_xdate(bottom=0.15)
dateFmt = matplotlib.dates.DateFormatter('%Y-%m-%d')
ax.xaxis.set_major_formatter(dateFmt)
plt.savefig(filename_stub+"_attacks_per_day_bar.png", format='png', dpi=300)

# Country look-up
warning_flag = 0
if len(sys.argv) < 4:
  # No raw attack info file specified, do look-up
  print("Querying ipinfo.io for origin of all attacking IPs - THIS MAY TAKE SOME TIME!")
  attacker_info_filename = filename_stub+"_raw_attacker_info.txt"
  f = open(attacker_info_filename, "w")
  for line in IP_unique:
    attacker_ele = subprocess.check_output("curl ipinfo.io/%s/geo" % line, shell=True)
    attacker_ele = attacker_ele.decode()
    f.write(attacker_ele)
    if "Rate limit exceeded" in attacker_ele and warning_flag == 0:
      print("WARNING: ipinfo look-up allowance exceeded - try later or subscribe to paid service")
      print("See terms of service at ipinfo.io")
      #warning_flag = 1
  f.close
  print("Completed ipinfo lookup - raw attacker info written to %s" % attacker_info_filename)
elif sys.argv[3] == "nolookup":
  print("WARNING: IP info country look-up disabled, selected analysis complete, exiting...")
  print(strftime("%Y-%m-%d_%H:%M:%S: All tasks completed, exiting fail2ban log analysis", gmtime()))
  sys.exit(0)
elif not os.path.isfile(sys.argv[3]):
  print("ERROR: Specified existing raw attacker info file cannot be found!")
  sys.exit(1)
else:
  attacker_info_filename = sys.argv[3]
  print("Reading attacker info from file %s" % attacker_info_filename)

warning_flag = 0
lastline =""
attacker_info_IPs = []
attacker_info_countries = []
attacker_info_lats = []
attacker_info_lons = []
with open(attacker_info_filename) as f:
  for line in f:
    if "Rate limit exceeded" in line and warning_flag == 0:
      print("WARNING: ipinfo look-up allowance exceeded - try tomorrow or subscribe to paid service")
      print("Note max free ipinfo look-ups is 1000 per day")
      warning_flag = 1
    split_line = line.split("\"")
    if "\"ip\":" in line:
      if not "null" in line:
        attacker_info_IPs.append(split_line[3])
      else:
        attacker_info_IPs.append("")
    if "\"country\":" in line:
      if not "null" in line:
        attacker_info_countries.append(split_line[3])
      else:
        attacker_info_countries.append("")
    if "\"loc\":" in line:
      if not "null" in line:
        locs = split_line[3].split(",")
        attacker_info_lats.append(locs[0])
        attacker_info_lons.append(locs[1])
      else:
        attacker_info_lats.append("")
        attacker_info_lons.append("")
    if "\"bogon\": true" in line or  ("\"ip\":" in lastline and "}{" in line):
      # Private or BOGON IP, or no data
      attacker_info_countries.append("")
      attacker_info_lats.append("")
      attacker_info_lons.append("")
    lastline = line

#print(attacker_info_IPs, attacker_info_countries, attacker_info_lats, attacker_info_lons)
IP_lookup_count = len(attacker_info_IPs)-attacker_info_IPs.count("")
country_lookup_count = len(attacker_info_countries)-attacker_info_countries.count("")
lat_lookup_count = len(attacker_info_lats)-attacker_info_lats.count("")
lon_lookup_count = len(attacker_info_lons)-attacker_info_lons.count("")
print("Searched info for %d IPs: found %d IP addresses, %d countries, %d lats and %d lons" % \
  (len(IP_unique), IP_lookup_count, country_lookup_count, lat_lookup_count, lon_lookup_count))

# If ipinfo lookup has consistent number of results with query, update results with location info and # attacks (yyyymmdd_fail2ban_attack_IPs_unique.csv - including geolocation)
if (len(IP_unique) == len(attacker_info_IPs) and len(IP_unique) == len(attacker_info_countries)) and len(IP_unique) == len(attacker_info_lats):
  print("Updating log of all UNIQUE attack IPs in %s to include location info" % IP_unique_filename)
  f = open(IP_unique_filename, "w")
  f.write("IP address,Number of Attacks,Country,Latitude,Longitude\n")
  counter = 0
  for line in IP_unique:
    f.write("%s,%s,%s,%s,%s\n" % (line, num_attacks[counter], attacker_info_countries[counter], attacker_info_lats[counter], attacker_info_lons[counter]))
    if line != attacker_info_IPs[counter]:
      print("WARNING: mismatch between IP query and result tables!")
    counter+= 1
  f.close
else:
  print("Country look-up data not available or incomplete - exiting")
  sys.exit(1)

# Use unique IP data as look-up table to add country to all-attack logs (yyyymmdd_fail2ban_attack_IPs_all.csv - including geolocation)
print("Updating log of all attack IPs in %s to include location info" % IP_log_filename)
f = open(IP_log_filename, "w")
f.write("Timestamp,IP address,Country,Latitude,Longitude\n")
counter = 0
attacker_info_countries_all = []
attacker_info_lats_all = []
attacker_info_lons_all = []
for line in IP:
  IP_unique_index = IP_unique.index(line)
  attacker_info_countries_all.append(attacker_info_countries[IP_unique_index])
  attacker_info_lats_all.append(attacker_info_lats[IP_unique_index])
  attacker_info_lons_all.append(attacker_info_lons[IP_unique_index])
  f.write("%s,%s,%s,%s,%s\n" % (datestamp[counter], line, attacker_info_countries_all[counter], attacker_info_lats_all[counter], attacker_info_lons_all[counter]))
  counter+= 1
f.close

# Use unique IP data as look-up table to add country to attack-unique-subnet logs (yyyymmdd_fail2ban_attack_IPs_unique_subnet.csv - including geolocation)
print("Updating log of all UNIQUE SUBNETS (assumes all IPs in /24 subnet co-located) in %s to include location info" % IP_subnet_filename)
f = open(IP_subnet_filename, "w")
f.write("Subnet (/24),Number of Attacks,Country,Latitude,Longitude\n")
counter = 0
attacker_info_countries_subnet = []
attacker_info_lats_subnet = []
attacker_info_lons_subnet = []
for line in IP_unique_subnet:
  IP_unique_index = IP_unique.index(line)
  attacker_info_countries_subnet.append(attacker_info_countries[IP_unique_index])
  attacker_info_lats_subnet.append(attacker_info_lats[IP_unique_index])
  attacker_info_lons_subnet.append(attacker_info_lons[IP_unique_index])
  f.write("%s.0,%s,%s,%s,%s\n" % (line.rsplit(".",1)[0], num_attacks_subnet[counter], attacker_info_countries_subnet[counter], attacker_info_lats_subnet[counter], attacker_info_lons_subnet[counter]))
  counter+= 1
f.close

# Create histogram tables to calculate country percentage of attacks for all IPs (yyyymmdd_fail2ban_attack_by_country_all_IPs.csv)
hist_all = Counter()
for line in attacker_info_countries_all:
  hist_all[line] += 1
countries_all = list(dict.keys(hist_all))
num_all = list(dict.values(hist_all))
pc_all = [float(x) * 100 / len(IP) for x in dict.values(hist_all)]
country_indices_all = sorted(range(len(num_all)), key=lambda k: num_all[k])
country_indices_all.reverse()
country_all_filename = filename_stub+"_attack_by_country_all_IPs.csv"
print("Writing logs of all attacks sorted by country to %s" % country_all_filename)
counter = 0
with open(country_all_filename, "w") as f:
  f.write("Country,Number of Attacks,Percentage\n")
  for line in countries_all:
    f.write("%s,%s,%s\n" % (countries_all[country_indices_all[counter]], num_all[country_indices_all[counter]], pc_all[country_indices_all[counter]]))
    counter += 1

# Create histogram tables to calculate country percentage of attacks for unique IPs (yyyymmdd_fail2ban_attack_by_country_unique_IPs.csv)
hist_unique = Counter()
for line in attacker_info_countries:
  hist_unique[line] += 1
countries_unique = list(dict.keys(hist_unique))
num_unique = list(dict.values(hist_unique))
pc_unique = [float(x) * 100 / len(IP_unique) for x in dict.values(hist_unique)]
country_indices_unique = sorted(range(len(num_unique)), key=lambda k: num_unique[k])
country_indices_unique.reverse()
country_unique_filename = filename_stub+"_attack_by_country_unique_IPs.csv"
print("Writing logs of all attacks from unique IP sorted by country to %s" % country_unique_filename)
counter = 0
with open(country_unique_filename, "w") as f:
  f.write("Country,Number of IPs,Percentage\n")
  for line in countries_unique:
    f.write("%s,%s,%s\n" % (countries_unique[country_indices_unique[counter]], num_unique[country_indices_unique[counter]], pc_unique[country_indices_unique[counter]]))
    counter += 1

# Create histogram tables to calculate country percentage of attacks for unique subnets (yyyymmdd_fail2ban_attack_by_country_unique_subnet.csv)
hist_subnet = Counter()
for line in attacker_info_countries_subnet:
  hist_subnet[line] += 1
countries_subnet = list(dict.keys(hist_subnet))
num_subnet = list(dict.values(hist_subnet))
pc_subnet = [float(x) * 100 / len(IP_unique_subnet) for x in dict.values(hist_subnet)]
country_indices_subnet = sorted(range(len(num_subnet)), key=lambda k: num_subnet[k])
country_indices_subnet.reverse()
country_subnet_filename = filename_stub+"_attack_by_country_unique_subnet.csv"
print("Writing logs of all attacks from unique subnet (/24) sorted by country to %s" % country_subnet_filename)
counter = 0
with open(country_subnet_filename, "w") as f:
  f.write("Country,Number of subnets,Percentage\n")
  for line in countries_subnet:
    f.write("%s,%s,%s\n" % (countries_subnet[country_indices_subnet[counter]], num_subnet[country_indices_subnet[counter]], pc_subnet[country_indices_subnet[counter]]))
    counter += 1

# Complete summary log
print("Updating summary log %s" % summary_filename)
top_3_country_string = ("Top 3 countries for most attacks:  1 %s (%s)" % (countries_all[country_indices_all[0]], num_all[country_indices_all[0]]))
if len(country_indices_all) >= 2:
  top_3_country_string += ("; 2 %s (%s)" % (countries_all[country_indices_all[1]], num_all[country_indices_all[1]]))
if len(country_indices_all) >= 3:
  top_3_country_string += ("; 3 %s (%s)" % (countries_all[country_indices_all[2]], num_all[country_indices_all[2]]))
top_3_country_string += "\n"
with open(summary_filename, "a") as f:
  f.write("Attacks total number of countries: %s\n" % len(countries_all))
  f.write(top_3_country_string)
  f.write("Analysis took %.1f seconds\n" % (time.time()-start_time))

# Plot country histograms - all (yyyymmdd_fail2ban_country_hist_all.png)
print("Plotting and saving graphs with country data...")
max_countries_plot = 25    # Set max number of x axis items on histogramps
max_countries_plot = min(max_countries_plot, len(countries_all))
countries_x = []
pc_all_plot =[]
countries_all_plot = []
for ii in range(0,max_countries_plot):
  countries_x.append(ii)
  pc_all_plot.append(pc_all[country_indices_all[ii]])
  countries_all_plot.append(countries_all[country_indices_all[ii]])
fig, ax = plt.subplots(1)
#print(countries_x, pc_all_plot, countries_all_plot)
plt.bar(countries_x, pc_all_plot, align='center')
plt.xticks(countries_x, countries_all_plot)
plt.ylabel('Proportion of attacks (%)')
plt.title("Attacks by country - all attacks\nFrom %s to %s (%s attacks)" % \
  (datestamp[0], datestamp[-1], len(IP)))
plt.xlim(countries_x[0]-1, countries_x[-1]+1)
plt.savefig(filename_stub+"_country_hist_all.png", format='png', dpi=300)

# Plot country histograms - unique (yyyymmdd_fail2ban_country_hist_unique_IP.png)
pc_unique_plot =[]
countries_unique_plot = []
for ii in range(0,max_countries_plot):
  pc_unique_plot.append(pc_unique[country_indices_unique[ii]])
  countries_unique_plot.append(countries_unique[country_indices_unique[ii]])
fig, ax = plt.subplots(1)
plt.bar(countries_x, pc_unique_plot, align='center')
plt.xticks(countries_x, countries_unique_plot)
plt.ylabel('Proportion of IP addresses (%)')
plt.title("Attacks by country - unique IP attacks\nFrom %s to %s (%s IPs)" % \
  (datestamp[0], datestamp[-1], len(IP_unique)))
plt.xlim(countries_x[0]-1, countries_x[-1]+1)
plt.savefig(filename_stub+"_country_hist_unique_IP.png", format='png', dpi=300)

# Plot country histograms - unique subnet (yyyymmdd_fail2ban_country_hist_unique_subnet.png)
pc_subnet_plot =[]
countries_subnet_plot = []
for ii in range(0,max_countries_plot):
  pc_subnet_plot.append(pc_subnet[country_indices_subnet[ii]])
  countries_subnet_plot.append(countries_subnet[country_indices_subnet[ii]])
fig, ax = plt.subplots(1)
plt.bar(countries_x, pc_subnet_plot, align='center')
plt.xticks(countries_x, countries_subnet_plot)
plt.ylabel('Proportion of /24 subnets (%)')
plt.title("Attacks by country - unique subnet (/24) attacks\nFrom %s to %s (%s subnets)" % \
  (datestamp[0], datestamp[-1], len(IP_unique_subnet)))
plt.xlim(countries_x[0]-1, countries_x[-1]+1)
plt.savefig(filename_stub+"_country_hist_unique_subnet.png", format='png', dpi=300)

print(strftime("%Y-%m-%d_%H:%M:%S: All tasks completed, exiting fail2ban log analysis", gmtime()))
