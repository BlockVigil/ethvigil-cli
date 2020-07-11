from setuptools import setup, find_packages

setup(
    name='ev-cli',
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        'console_scripts': ['ev-cli=click_cli:cli']
    },
    install_requires=[
        'eth-utils == 1.6.1',
        'requests == 2.22.0',
        'eth-account == 0.4.0',
        'solidity_parser == 0.0.7',
        'click == 7.0',
        "tenacity"
    ],
    classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
        ],
    version="0.1"
)