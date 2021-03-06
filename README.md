# Fox and the Hound

[![Python Version](https://img.shields.io/badge/Python-3.6-brightgreen.svg)]() [![license](https://img.shields.io/github/license/mashape/apistatus.svg)]()

![Fox](https://raw.githubusercontent.com/chrismaddalena/Fox/master/FoxAndTheHound.jpg)

## What Does Fox Do?

Fox connects to your BloodHound database to perform various queries to generate statistics about the target Active Directory environment. This includes:

* Total number of user objects
* Total number of computer objects
* Total paths to Domain Admin
* Average length of the paths to Domain Admin
* Average group membership
* Percentage of user's with a path to Domain Admin.
* Percentage of computer's with a path to Domain Admin.
* List of GPOs for review
* List of user accounts with old PwdLastSet timestamps
* List of computers that are not Domain Controllers with Domain Admin sessions
* Lists of Domain Admins, Enterprise Admins, and Administrators
* Count of the Local Admins on each computer object
* Count of unique operating systems seen in the environment
* Identifying non-standard groups with "Admin" in their names
* Identifying non-Admin groups with Local Admin privileges
* Identifying SPNs tied to Domain Admin accounts
* Identifying computers with Unconstrained Delegation

### Why?

Fox is a companion tool for BloodHound. Its intended purpose is to help both penetration testers and defenders analyze BloodHound data and better understand the target Active Directory environment. The goal is utilizing this data and understanding to make decisions, simulate those decisions in BloodHound, and then re-run Fox's calculations. The ultimate goal is finding changes that are feasible and affect a positive change on security posture and resiliency.

## Setup & Installation

Fox does not require anything beyond Python 3 and the Neo4j bolt driver (https://neo4j.com/developer/python/). However, you do need BloodHound data imported into a Neo4j project.

1. Start Neo4j like you normally would if you were preparing to use the BloodHound app for your platform.
2. Open Fox's database.config file and replace the default values with your Neo4j URI (probably the same as the default), username, and password.
3. Run Fox!

Fox is meant to assist you with queries you would normally have to execute in the Neo4j console, not BloodHound. In other words, there are no graphs and Fox is meant to act as a companion to BloodHound.

## Usage

### Get Your BloodHound Data

First of all, you need some BloodHound data. You *must* have data generated by the current version of BloodHound! The test database that comes with BloodHound lacks many of the labels and additional information used by Fox. Furthermore, make sure you run BloodHound with `-CollectionMethod All` to make sure you have all of the necessary data, like ObjectProps.

### Run Fox Against Your BloodHound Data

Fox has a few different modules, the details of which you can see in the help menu:

`python3 fox.py --help`

You can see the details of each module by viewing their help:

`python3 fox.py group --help`

#### Specifying a Domain

If your BloodHound data contains multiple domains you can specify a domain for Fox to use for the Cypher queries. If you do not, Fox will use all of the domains in the dataset.

Use the `-d` / `--domain` option to name a domain.

## Known Issues / Future Plans

For the initital commit Fox outputs data to your command line, but many queries return too much data for that to be practical. You may wish to see more of the data, like the usernames and dates for the old PwdLastSet query. Fox has the data, but doesn't dump it into the command line. Very soon there will be an option to dump verbose output into a spreadsheet.

Additional queries and calculations will continue to be added.