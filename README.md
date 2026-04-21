# SecretStroll-privacy-preserving-location-based-service
SecretStroll project for CS-523 Advanced topics on privacy enhancing technologies 2025 course at EPFL.

# SecretStroll

> **Note**: We have added separate README files for each part of the project. Please refer to them for part-specific descriptions.

## General Setup Instructions

Follow the steps below to set up the environment for running the project:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

For building Docker images and running them, nothing is changed, we use the steps provided in this original README file.

You need to switch directory to part1 directory where we include original Docker files, and follow the steps provided in the original project repository. After successfully building images, and executing server and client images respectively, you should be able to run part1 and part3 sample runs inside part1 folder where we have all necessary files: server.py, client.py, stroll.py, credential.py etc.

> **Note**: We have tested docker images and run SecretStroll with the current file structure in our submission described in README. In case you face some problems in the execution, just place all files inside "/part1" folder to main directory as it was in template repository and rerun all the steps in original README.

## Introduction

In this project, you will develop a location-based application, SecretStroll, that enables users to search for nearby points of interest (POI). 

### Code Skeleton

The first step of this project will be to retrieve the skeleton that you will
have to use as a base implementation. The most convenient way to do this will
be to clone the public repository of this course with `git`.

```
git clone https://github.com/spring-epfl/CS-523-public.git cs523
```

We use Python 3 in this project and all necessary Python components are already
installed on the VM and Docker containers. You can find installed libraries in
the file `requirements.txt`.

Feel free to have a look at `client.py` and `server.py` to see how the classes
and methods are used.

**Note:** The library `petrelic`is currently only distributed for Linux
systems, if you are not using the VM or a Linux system, you should still be
able to test your code by running it within the Docker containers build with
the provided configuration.

### Collaboration

You can use git to sync your work with your teammates. However, keep in mind
that you are not allowed to use public repositories, so make sure that your
repository is **private**.

If you cloned our git repository to retrieve the skeleton as we advised, you
can replace the remote URL to your own git repository

```
cd cs523
git remote set-url origin git@github.com:<your GitHub user ID>/<your private repo>
```

## Files in this repository

This repository contains the skeleton code for Parts 1 and 3:

* `credential.py`—Source code that you have to complete.
* `stroll.py`—Source code that you have to complete.
* `client.py`—Client CLI calling classes and methods defined in `stroll.py`.
* `server.py`—Server CLI calling classes and methods defined in `stroll.py`.
* `serialization.py`—Extends the library `jsonpickle` to serialize python
  objects.
* `fingerprinting.py`—skeleton for Part 3.
* `requirements.txt`—Required Python libraries.
* `docker-compose.yaml`—*docker compose* configuration describing how to run the
  Docker containers.
* `docker/`—Directory containing Docker configurations for running the client
  and the server.
* `tor/`—Intentionally empty folder needed to run a Tor server.
* `fingerprint.db`—Database containing POI information for Part 3.

The directory `privacy_evaluation` contains files for the part 2.

## Server and client deployment

The server and client code deployment is handled by Docker and our skeleton. In
this section, we introduce our Docker infrastructure and how to use it. Then, we
provide a step-by-step guide of running the client and server.

### Working with the Docker infrastructure

*Before launching the infrastructure, ensure the `tor` directory in the project's
directory has the correct permissions.*
```
student@cs523:~$ cd cs523/secretstroll/
student@cs523:~/cs523/secretstroll$ chmod 777 tor
student@cs523:~/cs523/secretstroll$ ls -ld tor
drwxrwxrwx 2 student student    4096 mar 24 15:31 tor
```

The server and the client run in a Docker infrastructure composed of 2
containers, and a virtual network.

Before setting up the Docker infrastructure for the first time, you must first
build the images which will be used to run the client and server containers. To
do so, run the following command in the directory which contains the
file `docker-compose.yml`:
```
docker compose build
```

To set up the Docker infrastructure, run the following command in the directory
containing the file `docker-compose.yml`:
```
docker compose up -d
```

When you stop working with the infrastructure, remember to shut it down by
running the following command in the `secretstroll` directory containing the file
`docker-compose.yml`:
```
docker compose down
```

**Note:** *If you forget to shut down the Docker infrastructure, e.g., before
shutting down your computer, you might end up with stopped Docker containers
preventing the creation of the new ones when you to re-launch the infrastructure
the next time. This can be fixed by removing the network bridge with
`docker compose down` and destroying the stopped Docker containers with
`docker container prune -f`.*

### Accessing the data

The code in the `secretstroll` directory is shared between your VM and the
Docker containers, so modifications you make in your VM will also appear in
containers. Feel free to read the file `docker-compose.yml` to see how it is
done.

If you need to transfer some data between your VM and your host machine, you
can set up SSH access and use the `scp` command as detailed before.

Another option for people who use VirtualBox is to have shared directories
between the VM and your host. For this feature to work correctly you need to
have VirtualBox's *Guest Additions* installed on the VM. We have already
installed *Guest Additions* on the VM we provided for this course, but you
might have to update it to work with your version of VirtualBox, in which case,
please refer to their documentation.

Note also that you will need to use Tor in this project (see section below),
and that Tor is quite sensitive to its directories' permissions. As it is often
not possible to map directly the permission between the host and guest when
sharing some files, be careful to not run your project directly from the shared
directory as incorrect permission given to the `tor` directory of your project
can prevent Tor from starting.

### Tor integration

Integrating Tor into your project should be seamless. The Docker configuration
we provide is designed to run Tor in the background, and the code is designed
to use the Tor if requested with no effort on your part.

If your project works if used normally, but fails when using Tor, you can check
if its log file in the Docker container gives a clue to what is happening:

```
cat /var/log/service/tor/current
```

If you still do not know what causes the problem or do not know how to correct
it, call an assistant.

### Server

It is easier to run the commands in a Docker container by opening a shell, and
then running the commands inside this shell.

To execute a shell in the container in which the server is to be launched, run
the following command:

```
docker exec -it cs523-server /bin/bash
```

In this container, the root directory of the project is mounted on `/server`.
```
cd /server
```

The server has two subcommands: `gen-ca` and `run`. `gen-ca` generates
the public and secret keys, and `run` runs the server. The server and its
subcommands have a help option, which you can access using the `-h` argument.

Key generation example:
```
python3 server.py setup -S restaurant -S bar -S sushi

usage: server.py setup [-h] [-p PUB] [-s SEC] -S SUBSCRIPTIONS

optional arguments:
  -h, --help            show this help message and exit
  -p PUB, --pub PUB     Name of the file in which to write the public key.
                        (default: key.pub)
  -s SEC, --sec SEC     Name of the file in which to write the secret key.
                        (default: key.sec)
  -S SUBSCRIPTIONS, --subscriptions SUBSCRIPTIONS
                        Subscriptions recognized by the server.
```

Server run example:
```
python3 server.py run

usage: server.py run [-h] [-D DATABASE] [-p PUB] [-s SEC]

optional arguments:
  -h, --help            show this help message and exit
  -D DATABASE, --database DATABASE
                        Path to the PoI database.
  -p PUB, --pub PUB     Name of the file containing the public key.
  -s SEC, --sec SEC     Name of the file containing the secret key.
```

In the Part 3 of the project, the server is expected to be accessible as a Tor
hidden service. The server's Docker container configures Tor to create a hidden
service and redirects the traffic to the Python server. The server serves local
and hidden service requests simultaneously by default.

The server also contains a database, `fingerprint.db`. This is used in Part 3.
The database has a POI table that contains records for each POI. The server
returns the list of POIs associated with a queried cell ID, and information
about each POI in the list. You must not modify the database.

### Client

To execute a shell in the client container, run the following command:

```
docker exec -it cs523-client /bin/bash
```

In this container, the root directory of the project is mounted on `/client`.
```
cd /client
```

The client has four subcommands: `get-pk`, `register`, `loc`, and `grid`. As for
the server, the client and its subcommands have a help option, which you can
access using the `-h` argument.

Use `get-pk` to retrieve the public key from the server:
```
python3 client.py get-pk

usage: client.py get-pk [-h] [-o OUT] [-t]

optional arguments:
  -h, --help         show this help message and exit
  -o OUT, --out OUT  Name of the file in which to write the public key.
                     (default: key-client.pub)
  -t, --tor          Use Tor to connect to the server.
```

Use `register` to register an account on the serve:
```
python3 client.py register -u your_name -S restaurant -S bar

usage: client.py register [-h] [-p PUB] -u USER [-o OUT] -S SUBSCRIPTIONS [-t]

optional arguments:
  -h, --help            show this help message and exit
  -p PUB, --pub PUB     Name of the file from which to read the public key.
                        (default: key-client.pub)
  -u USER, --user USER  User name.
  -o OUT, --out OUT     Name of the file in which to write the attribute-based
                        credential. (default: anon.cred)
  -S SUBSCRIPTIONS, --subscriptions SUBSCRIPTIONS
                        Subscriptions to register.
  -t, --tor             Use Tor to connect to the server.
```

Use `loc` and `grid` commands to retrieve information about points of interests
using lat/lon location (Part 1) and cell identifier (Part 3), respectively:
```
python3 client.py loc 46.52345 6.57890 -T restaurant -T bar

usage: client.py loc [-h] [-p PUB] [-c CREDENTIAL] -T TYPES [-t] lat lon

positional arguments:
  lat                   Latitude.
  lon                   Longitude.

optional arguments:
  -h, --help            show this help message and exit
  -p PUB, --pub PUB     Name of the file from which to read the public key.
                        (default: key-client.pub)
  -c CREDENTIAL, --credential CREDENTIAL
                        Name of the file from which to read the attribute-
                        based credential. (default: anon.cred)
  -T TYPES, --types TYPES
                        Types of services to request.
  -t, --tor             Use Tor to connect to the server.
```

**Warning**: The database only contains points of interest with latitude in
range \[46.5, 46.57\] and longitude in range \[6.55, 6.65\] (Lausanne area).
You can make queries outside these values, but you will not find anything
interesting.

```
python3 client.py grid 42 -T restaurant

usage: client.py grid [-h] [-p PUB] [-c CREDENTIAL] [-T TYPES] [-t] cell_id

positional arguments:
  cell_id               Cell identifier.

optional arguments:
  -h, --help            show this help message and exit
  -p PUB, --pub PUB     Name of the file from which to read the public key.
                        (default: key-client.pub)
  -c CREDENTIAL, --credential CREDENTIAL
                        Name of the file from which to read the attribute-
                        based credential. (default: anon.cred)
  -T TYPES, --types TYPES
                        Types of services to request.
  -t, --tor             Use Tor to connect to the server.
```

## A sample run of Part 1
Here we show a typical run of the system for Part 1.

Initialization:


Open a shell
```
$ cd cs523/secretstroll
$ docker compose build
$ docker compose up -d
```

Server side:

Open a shell
```
$ cd cs523/secretstroll
$ docker exec -it cs523-server /bin/bash
(server) $ cd /server
(server) $ python3 server.py setup -s key.sec -p key.pub -S restaurant -S bar -S dojo
(server) $ python3 server.py run -D fingerprint.db -s key.sec -p key.pub
```

Client side:
```
Open a shell
$ cd cs523/secretstroll
$ docker exec -it cs523-client /bin/bash
(client) $ cd /client
(client) $ python3 client.py get-pk
(client) $ python3 client.py register -u your_name -S restaurant -S bar -S dojo
(client) $ python3 client.py loc 46.52345 6.57890 -T restaurant -T bar
```

Close everything down at the end of the experiment:
```
$ docker compose down
```

## A sample run of Part 3
Here we provide a typical run of the system for Part 3:

Initialization:

```
Open a shell
$ cd cs523/secretstroll
$ docker compose build
$ docker compose up -d
```

Server side:

You should have already generated the keys in Part 1, so you do not need to
repeat that step.

```
Open a shell
$ cd cs523/secretstroll
$ docker exec -it cs523-server /bin/bash
(server) $ cd /server
(server) $ python3 server.py run
```

Client side:

You should have already performed the registration in Part 1, so you do not need
to the repeat the step. Use the grid parameter to query for a particular cell.
Set the reveal argument (-r) to an empty value. Set the -t argument to use Tor. The example run below queries the server for cell ID = 42.

```
Open a shell
$ cd cs523/secretstroll
$ docker exec -it cs523-client /bin/bash
(client) $ cd /client
(client) $ python3 client.py grid 42 -T restaurant -t
```

Close everything down at the end of the experiment:
```
$ docker compose down
```
