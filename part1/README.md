## Part1 README

### ABC scheme and SecretStroll integration
To do sample runs of SecretStroll system, you need to do the following:

For building Docker images and running them, nothing is changed, we use the steps provided in the original project README file.

You need to switch directory to part1 directory where we include original Docker files, and follow the steps provided in the original project repository. After successfully building images, and executing server and client images respectively, you should be able to run part1 and part3 specific sample runs where we have all necessary files: server.py, client.py, stroll.py, credential.py etc.

Below we provide these steps again for ease of reference:

## A sample run of Part 1
Here we show a typical run of the system for Part 1.

Initialization:


Open a shell
```
$ cd secretstroll/part1
$ docker compose build
$ docker compose up -d
```

Server side:

Open a shell
```
$ cd secretstroll/part1
$ docker exec -it cs523-server /bin/bash
(server) $ cd /server
(server) $ python3 server.py setup -s key.sec -p key.pub -S restaurant -S bar -S dojo
(server) $ python3 server.py run -D fingerprint.db -s key.sec -p key.pub
```

Client side:
```
Open a shell
$ cd secretstroll/part1
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

### Tests
To run test suite for part 1 of the project:

`python3 -m pytest tests.py`

To run individual test suites follow the guidance below:

- Test only PS signature functionality

`python3 -m pytest tests.py::TestPSSignature -v`

- Test ABC credential system operations

`python3 -m pytest tests.py::TestCredentialSystem -v`

- Test SecretStroll integration

`python3 -m pytest tests.py::TestSecretStrollIntegration -v`

- Test failure conditions

`python3 -m pytest tests.py::TestFailureConditions -v`

- Test complete credential lifecycle

`python3 -m pytest tests.py::TestCompleteCredentialLifecycle -v`

### Performance Evaluation
To run performance evaluation script with 100 trials: 

`python3 performance_evaluation.py --trials 100`
