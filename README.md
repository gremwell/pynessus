# PyNessus

|build-status| |docs|

Client for the Nessus vulnerability scanner REST API. Currently support Nessus versions >= 5.0. All exposed functionnalities
are implemented.

## Features

* Full support of Nessus functionalities

## Installation

You can install pynessus either via pip or by cloning the repository :

```shell
$ pip install python-nessus
```

```shell
$ git clone https://github.com/QKaiser/pynessus.git pynessus
$ cd pynessus
$ python setup.py install
```

```shell
quentin@grmwl$ python
Python 2.7.6 (default, Mar 22 2014, 22:59:56)
[GCC 4.8.2] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pynessus import Nessus
>>> Nessus()
<pynessus.nessus.Nessus object at 0x7f2a6f5aae50>
```

## Documentation

The full documentation is available at https://pynessus.readthedocs.org . You can find example scripts under the
scripts directory.

## Contribute

* Issue Tracker: https://github.com/QKaiser/pynessus/issues
* Source Code: https://github.com/QKaiser/pynessus

## Support

If you are having issues, please let me know via the issue tracker or by mail (quentin@gremwell.com).

## License

The project is licensed under the Apache 2.0 License.

## Credits

Original ideas were taken from https://code.google.com/p/nessusxmlrpc by Kurtis Miller
