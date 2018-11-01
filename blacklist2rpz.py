#!/usr/bin/python

import yaml
import time
import re
import os
import sys
import subprocess
import requests
import hashlib
from jinja2 import Environment, FileSystemLoader

validHostname  = re.compile(r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$')
masterBlacklist = {}

# Config file processing
configDir = '/etc/blacklist2rpz'
config = {}
if os.path.isfile ( "{}/config.yaml".format( configDir) ):
    with open ( "{}/config.yaml".format( configDir), 'r' ) as f:
        config.update ( yaml.safe_load(f) )
else:
    sys.exit ( "Configuration file %s not found\n" % configFile )

# Create the temporary directory and cachefile if not present
cacheFile = "{}/cache.yaml".format(config['tempDir'])
cache = {}
if not os.path.isdir(config['tempDir']):
    os.makedirs(config['tempDir'])
elif os.path.isfile(cacheFile):
    with open ( cacheFile, 'r' ) as f:
        cache.update(yaml.safe_load(f))

# Setting Up Jinja2 Template
env = Environment(
    loader = FileSystemLoader( configDir )
)
template = env.get_template('rpz_zone.j2')

timestamp = int(time.time())
zoneName=config['zoneName']

def downloadBlacklist(blacklist, tempDir, cache):
    print "Checking {} from {}".format(blacklist['name'], blacklist['url'])
    if blacklist['name'] in cache:
        if 'download' in cache[blacklist['name']] and 'eTag' in cache[blacklist['name']]['download']:
            r = requests.head(blacklist['url'])
            if cache[blacklist['name']]['download']['eTag'] == r.headers['ETag']:
                if 'file' in cache[blacklist['name']]['download'] and os.path.isfile(cache[blacklist['name']]['download']['file']):
                    with open(cache[blacklist['name']]['download']['file'], 'rb') as f:
                        if cache[blacklist['name']]['download']['hash'] == hashlib.sha256(f.read()).hexdigest():
                            return
        else:
            cache[blacklist['name']] = {'download' : {}}
    else:
        cache[blacklist['name']] = {'download' : {}}
    print "Downloading {}".format(blacklist['name'])
    r = requests.get(blacklist['url'], headers={'user-agent': 'blacklist2rpz'})
    downloadFile = "{}/{}-download-Cache.txt".format(tempDir, blacklist['name'])
    with open(downloadFile, 'wb') as f:
        f.write(r.content)
    if 'ETag' in r.headers:
        cache[blacklist['name']]['download']['eTag'] = r.headers['ETag']
        cache[blacklist['name']]['download']['hash'] = hashlib.sha256(r.content).hexdigest()
    cache[blacklist['name']]['download']['file'] = downloadFile
    return

def processBlacklist(blacklist, tempDir, cache):
    print "Processing {}".format(blacklist['name'])
    listing = list()
    with open(cache[blacklist['name']]['download']['file'], 'r') as f:
        temp = f.read().splitlines()
    for x in temp:
        if x == '':
            continue
        elif x[0] == '#':
            continue
        else:
            if blacklist['format'] == 'hostsFile':
                for y in x.split()[1::]:
                    if validHostname.match(y):
                        if y in config['exclusions']:
                            print "{} Excluded from listing in {}".format(y, blacklist['name'])
                        else:
                            listing.append(y)
            else:
                for y in x.split():
                    if validHostname.match(y):
                        if y in config['exclusions']:
                            print "{} Excluded from listing in {}".format(y, blacklist['name'])
                        else:
                            listing.append(y)
    return listing

remoteBlacklists = list()
for listing in config['remoteBlacklists']:
    if 'policy' in listing:
        policy = listing['policy']
        if listing['policy'] is 'Local-Data':
            policyOverrides = listing['policy-overrides']
    else:
        policy = config['defaultPolicy']
    downloadBlacklist(listing, config['tempDir'], cache)
    if policy is 'Local-Data':
        remoteBlacklists.append({'name' : listing['name'], 'policy' : policy, 'policy-overrides' : policyOverrides, 'source' : listing['url'],  'list' : processBlacklist(listing, config['tempDir'], cache)})
    else:
        remoteBlacklists.append({'name' : listing['name'], 'policy' : policy, 'source' : listing['url'],  'list' : processBlacklist(listing, config['tempDir'], cache)})
    print ""

print "\n\nDone Processing all lists\n\n"

# Saving Cachefile
print "Saving Cache file"
with open(cacheFile, 'w') as f:
    yaml.dump(cache, f)

print "Working on Jinja2 Template"
print
outputdata = template.render(remoteBlacklists=remoteBlacklists, timestamp=timestamp, zoneName=zoneName)
# write the config['rpzFile'] file
with open ( config['rpzFile']+'.TMP', 'wt' ) as f:
    f.write ( outputdata )
os.rename ( config['rpzFile'], config['rpzFile']+'.old' )
os.rename ( config['rpzFile']+'.TMP', config['rpzFile'] )
# reload bind zone file
p = subprocess.call(['rndc', 'reload', zoneName])

#    # Remove Whitelist
#    for host in config['exclusions'].iterkeys():
#        tempHosts.discard(host)
#
#    # if we have a local blacklist, add that also
#    if 'localblacklist' in config:
#        for host in config['localblacklist']:
#            tempHosts.add(host)
#


#    testing for valid domain names sed -E '/(\.|\/)(([A-Za-z\d]+|[A-Za-z\d][-])+[A-Za-z\d]+){1,63}\.([A-Za-z]{2,3}\.[A-Za-z]{2}|[A-Za-z]{2,6})/!d'
