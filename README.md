# fail2ban-analyse
Performs analysis of Fail2ban logs and outputs data in CSV, PNG and text formats plus a map overlay of IPs

## Description

These scripts analyse Fail2ban logfiles to show the how the rate of attacks varies over time, which IPs and IP ranges are attempting access and from which countries these IPs originate. The locations are plotted on a map overlay showing location, IP and number of attacks. Raw data and charts provide deeper analysis.

## How to use

Ensure curl is installed, and Python3 with matplotlib and geojson modules. The simplest way to get started is to run the wrapper script straight from the root of the repo (assuming you have logs in default /var/log/)
`./fail2ban_analyse_wrapper.sh`
This will run full analysis on all available logs in /var/log, and store full results in _outputs_ and generated web content in _web_

To change any of the input or output directories, edit _config/fail2ban_analyse.conf_

After running, the contents of _web_ can be moved to your webserver directory (the map overlays only work in-browser, although a server is not necessarily needed and all other images are output as static PNGs).  Note _attacker-map.html_ requires editing to add your mapbox API key, whereas _attacker-map-openstreetmap.html_ works straight out of the box.

The wrapper shell script calls the two main Python scripts:
- _scripts/fail2ban_analyse.py_ which parses and analyses fail2ban (and optionally auth/secure) logs and performs geo-lookup for all the IPs found, returning results in TXT, CSV and PNG formats.
- _scripts/create-attacks-geojson.py_ which converts one of the CSV outputs above into a GeoJSON file which can be used to overlay IPs and number of attacks on a map

## Example outputs

![Example map overlay](/examples/map-screenshot.png)
![Example satellite view](/examples/satellite-screenshot.png)
![Example Attack timeline](/examples/unauth-example.png)

## Requirements

- Python3 with standard modules + **matplotlib** and **geojson**
- Standard Linux CLI tools including **curl**
- (optional) A webserver for displaying map overlay (or view locally in browser)
- (optional) A Mapbox API key (if using Mapbox version)
- Only tested on Linux

## Inputs

- Fail2ban logs to analyse. These may be rotated in Debian pattern (.1, .2, etc) or CentOS/Fedora (-yyyymmdd, etc). They will be un-rotated, uncompressed if they end .gz and appended in date order for analysis. Inside the logs, standard timestamps in form _'yyyy-mm-dd HH:MM:SS,'_ are required, and all logs matching pattern _fail2ban.log*_ in input directory will be analysed
- A valid configuration file in _/etc/fail2ban_analyse.conf_ or relative path _config/fail2ban_analyse.conf_ specifying input and output directories - an example can be found in _config/_
- (optional) auth or secure log(s) if SSH username analysis is required. If available in same input directory auth* and secure* in plain text format only will be analysed to find most common invalid usernames used in SSH login attempts
- (optional) if using Mapbox, a Mapbox API key is required. Sign up for a free Mapbox account using link below and paste the API key into the appropriately commented section in _attacker-map.html_. Alternatively, use the openstreetmap version _attacker-map-openstreetmap.html_ which requires no modification

## Outputs

Outputs are provided in PNG (charts), CSV and TXT formats, as well as GeoJSON for the map overlay. Results are grouped into three categories (i) considering each unauthorised access attempt separately, (ii) grouping by attacks from the same IP address and (iii) grouping by a /24 subnet (although of course this does not imply the IP belongs to a /24 subnet). This is useful for profiling attackers, because it will be seen that some countries tend to produce a small number of attacks from several unique IPs, whereas others have a much larger number of attacks but many originate from the same IP or blocks of IPs. Of course this is also affected by the Fail2ban configuration.

In web directory (_web/_ or value of OUTPUT_DIR_WEB set in the config file):

```
attacks-geojson.js - GeoJSON file containing IP, country, number of attacks for creating leaflet map overlay
unauth-country.png - bar chart of attack origin by country, expressed as percentage
unauth.png - bar chart showing number of attacks per day, and summary of worst offenders
```

(note _attacker-map.html_ and/or _attacker-map-openstreetmap.html_ will also be required in the web server directory in order to view map overlays)

In full output directory (_outputs/_ or value of OUTPUT_DIR_HISTORICAL set in the config file):
```
yyyymmdd_fail2ban_all_raw_logs.txt - all raw input logs, un-rotated, uncompressed and appended in timestamp order
yyyymmdd_fail2ban_attack_by_country_all_IPs.csv - list of countries with absolute number of attacks and percentage (raw data for chart below)
yyyymmdd_fail2ban_attack_by_country_unique_IPs.csv - list of countries with absolute number of unique IPs and percentage (raw data for chart below)
yyyymmdd_fail2ban_attack_by_country_unique_subnet.csv - list of countries with absolute number of unique IP subnet (assuming /24) and percentage (raw data for chart below)
yyyymmdd_fail2ban_attack_IPs_all.csv - list of all attacks showing timestamp, IP, country, approximate coordinates
yyyymmdd_fail2ban_attack_IPs_unique.csv - list of all attacks showing IP, number of attacks, country, approximate coordinates
yyyymmdd_fail2ban_attack_IPs_unique_subnet.csv - list of all attacks showing IP subnet (grouping into /24), number of attacks, country, approximate coordinates
yyyymmdd_fail2ban_attacks_per_day_bar.png - bar chart showing number of attacks per day, and summary of worst offenders (same as unauth.png)
yyyymmdd_fail2ban_country_hist_all.png - bar chart of attack origin by country, expressed as percentage (same as unauth-country.png)
yyyymmdd_fail2ban_country_hist_unique_IP.png - bar chart of IP address origin by country, expressed as percentage
yyyymmdd_fail2ban_country_hist_unique_subnet.png - bar chart of IP subnet (grouping into /24) origin by country, expressed as percentage
yyyymmdd_fail2ban_log_analysis_summary.txt text summary of key results
yyyymmdd_fail2ban_raw_attacker_info.txt - raw JSON results of ipinfo.io lookup - this may also be used as an input to avoid re-running lookup
usernames.txt - (if valid uncompressed auth*/secure* logs found in input log directory, SSH only) a list of invalid usernames used in failed SSH access attempts
```
(note country / coordinate info will not be available if nolookup option is used to prevent ipinfo.io lookups)

## Dependencies

- ipinfo.io is used for geolocation of IP addresseses.  If calling _fail2ban_analyse.py_ a command line argument can be used to specify an existing results file from a previous lookup, or skip look-up altogether (with reduced functionality).  Requests to ipinfo.io API are subject to their terms of use and limits on number of lookups - paid plans are required for heavier use.
- Mapbox API key is required if using Mapbox (_attacker-map.html_).  You can obtain this for free by signing up with Mapbox.  Openstreetmap version (_attacker-map-openstreetmap.html_) does not require this.
- CDNs are used for Leaflet and OMS, for a fully locally hosted version simply download leaflet (leaflet.js, leaflet.css and images directory) and OMS (oms.min.js) and edit the html accordingly
- a favicon is referenced at _favicon.ico_ in same directory as the map html files but not supplied and may be added if required

## Automation

These scripts are intended to be run automatically, periodically, e.g. by cron. It is recommended that the config file is moved to /etc and this config file updated to point to the required input and output directories, and script directory when "installed" rather than run from repo directly. The outputs to the web server directory always have the same filename, so they can easily be accessed and linked to but only contain latest data, whereas the full output directory stores datestamped files for later reference.

For example adding to cron `10 6 * * 0 /usr/local/bin/fail2ban_analyse_wrapper.sh >>/var/log/f2b-analysis.log` will run every Sunday morning just before logs are typically rotated on many Linux systems, and store the output in a logfile.

## References

- http://www.fail2ban.org/
- https://ipinfo.io/
- https://leafletjs.com/
- https://www.mapbox.com/
- https://www.openstreetmap.org/
- https://github.com/jawj/OverlappingMarkerSpiderfier-Leaflet



