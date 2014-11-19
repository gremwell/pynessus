# PyNessus : Nessus REST API client.

python-nessus is an Apache 2 Licensed Nessus library, written in Python, for security auditors and pentesters.

## Features Support

* Users management
* Policies management
* Scans management
* Tags management
* Schedules management
* Reports management

## User Guide

### Introduction

### Installation

You can install python-nessus either via pip or by cloning the repository.

```
$ pip install python-nessus
```

```
$ git clone https://github.com/QKaiser/pynessus.git pynessus
$ cd pynessus
$ python setup.py install
```

### Quickstart

#### Connect to a Nessus Server

```python
from pynessus import Nessus
from pynessus.models.user import User
server = Nessus("localhost", 8834)
if server.login(User("username", "password")):
    print "Success!"
else:
    print "Fail!"
```

#### Manage policies

```python
from pynessus import Nessus
from pynessus.models.user import User
from pynessus.models.policy import Policy
server = Nessus("localhost", 8834)
if server.login(User("username", "password")):
    server.load_policies()
    # display available policies
    for policy in server.policies:
        print "%s - %s" % (policy.db_id, policy.name)
        
    # creating a policy
    p = server.Policy()
    p.name = "My new policy"
    if p.save():
        print "[+] Policy %s successfully created." % p.name
    else:
        print "[!] An error occured while creating policy %s" % p.name
        
    # updating a policy
    p.description = "Let's set a description."
    if p.save():
        print "[+] Policy %s successfully updated." % p.name
    else:
        print "[!] An error occured while updating policy %s" % p.name

    # downloading nessus xml policy description
    path = p.download():
    if path is not None:
        print "[+] Policy %s successfully downloaded to %s." % (p.name, path)
    else:
        print "[!] An error occured while downloading policy %s" % p.name
    
    # deleting a policy
    if p.delete():
        print "[+] Policy %s successfully deleted." % p.name
    else:
        print "[!] An error occured while deleting policy %s" % p.name
else:
    print "Fail!"
```

#### Manage scans

* Create a scan, pause, stop, delete

```python
import time
from pynessus import Nessus
from pynessus.models.user import User
from pynessus.models.policy import Policy

server = Nessus("localhost", 8834)

if server.login(User("username", "password")):

    server.load_scans()
    # display scans
    for scan in server.scans:
        print "%s - %s" % (scan.uuid, scan.name)
        
    # creating a scan
    s = server.Scan()
    s.name = "My new scan"

    if s.launch():
        print "[+] Scan %s successfully launched." % s.uuid
        # pausing the scan
        if s.pause():
            print "[+] Scan %s has been paused." % s.uuid
            time.sleep(10)
            # resuming the scan
            if s.resume():
                print "[+] Scan %s has been resumed." % s.uuid
                time.sleep(10)
                # stopping the scan
                if s.stop():
                    print "[+] Scan %s has been stopped." % s.uuid
                else:
                    print "[!] An error occured when stopping scan %s." % s.uuid 
            else:
                print "[!] An error occured when resuming scan %s." % s.uuid 
        else:
            print "[!] An error occured when pausing scan %s." % s.uuid         
        # deleting scan
        if s.delete():
            print "[+] Scan %s has been deleted." % s.uuid
        else:
            print "[!] An error occured when deleting scan %s." % s.uuid 
    else:
        print "[!] An error occured while launching scan %s" % s.name
else:
    print "Fail!"
```


#### Manage tags

* Create a tag, move a scan from one tag to another, delete all scans from a specifc tag

```python
from pynessus import Nessus
from pynessus.models.user import User
from pynessus.models.tag import Tag

server = Nessus("localhost", 8834)

if server.login(User("username", "password")):

    server.load_tags()
    # display tags
    for tag in server.tags:
        print "%s - %s" % (tag.id, tag.name)
        
    # creating a tag
    t = server.Tag()
    t.name = "My new tag"

    if t.save():
        print "[+] Tag %s successfully created." % t.name
        # updating tag
        t.name = "Another name"
        if t.save():
            print "[+] Tag %s has been updated." % t.name
        else:
            print "[!] An error occured while updating Tag %s." % t.name
        #deleting tag
        if t.delete():
            print "[+] Tag %s has been deleted." % t.name
        else:
            print "[!] An error occured while deleting Tag %s." % t.name
else:
    print "Fail!"
```

#### Manage schedules


```python
from pynessus import Nessus
from pynessus.models.user import User
from pynessus.models.schedule import Schedule

server = Nessus("localhost", 8834)

if server.login(User("username", "password")):

    server.load_schedules()
    # display schedules
    for s in server.schedules:
        print "%s - %s" % (s.id, s.name)
        
    # creating a schedule
    s = Schedule()
    s.name = "My new schedule"
else:
    print "Fail!"
```

## API Documentation

Documentation generated from docstring.

## Contributor Guide

### Development Philosophy

* Semantic versioning
* PEP8 compliance
* Comment your shit

### How to Help

python-nessus is under active development, and contributions are more than welcome!

Check for open issues or open a fresh issue to start a discussion around a bug.
Fork the repository on GitHub and start making your changes to a new branch.
Write a test which shows that the bug was fixed.
Send a pull request and bug the maintainer until it gets merged and published. :) Make sure to add yourself to AUTHORS.

#### Test suite:

```
$ python -m unittest test.py
.........................
25 passed in 3.50 seconds
```

#### Runtime Environments

python-nessus currently supports the following versions of Python:

* Python 2.6
* Python 2.7

## Authors

* Quentin Kaiser (quentin@gremwell.com)