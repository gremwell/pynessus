from distutils.core import setup
VERSION = __import__("pynessus").__version__
CLASSIFIERS = [
    'Development Status :: 3 - Alpha',
    'Environment :: Console',
    'Intended Audience :: System Administrators',
    'License :: OSI Approved :: Apache Software License',
    'Natural Language :: English',
    'Programming Language :: Python :: 2.7',
    'Topic :: Security',
    'Operating System :: OS Independent',
]
setup(
    name="python-nessus",
    description="Nessus python client.",
    version=VERSION,
    author="Quentin Kaiser",
    author_email="quentin@gremwell.com",
    url="https://github.com/qkaiser/pynessus",
    download_url="https://github.com/qkaiser/pynessus/releases/latest",
    package_dir={'pynessus': 'pynessus', 'pynessus.models': 'pynessus/models'},
    packages=['pynessus', 'pynessus.models'],
    classifiers=CLASSIFIERS,
)
