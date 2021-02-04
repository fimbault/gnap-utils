#!/usr/bin/python3

import re
import subprocess
import urllib.request
import json 
import time

openiss = []
closediss = []

with open('draft-ietf-gnap-core-protocol.md') as f:
    lines = f.readlines()
    for l in lines:
        print('.', end='', flush=True)
        m = re.search('\[See issue #(\d\d\d?)\]', l)
        if m:
            iss = m.group(1)
            print('#%s' % iss, end='', flush=True)
            #print(l)
            #print(iss)
            
            done = subprocess.run(['gh', 'issue', 'view', iss], text=True, capture_output=True)
            
            #print(done.stdout)
            
            s = re.search('state:\t(OPEN|CLOSED)', done.stdout)
            
            status = s.group(1)

            if status == 'OPEN':
                openiss.append(iss)
            elif status == 'CLOSED':
                closediss.append(iss)
            else:
                print()
                print('Unknown status for %s: %s' % (iss, status))

            
            #with urllib.request.urlopen("https://api.github.com/repos/ietf-wg-gnap/gnap-core-protocol/issues/%s" % iss) as url:
            #    data = json.loads(url.read().decode())
            #    status = data['state']
            
            #    if status == 'open':
            #        openiss.append(iss)
            #    elif status == 'closed':
            #        closediss.append(iss)
            #    else:
            #        print()
            #        print('Unknown status for %s: %s' % (iss, status))
                
            #    time.sleep(0.2) # try not to hit the rate-limit

print()                
print('Open issues (%d): ' % len(openiss))

for i in openiss:
    print('   https://github.com/ietf-wg-gnap/gnap-core-protocol/issues/%s' % i)

print('Closed issues (%d): ' % len(closediss))

for i in closediss:
    print('   https://github.com/ietf-wg-gnap/gnap-core-protocol/issues/%s' % i)
