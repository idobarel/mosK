from setuptools import setup, find_packages
import codecs
import os

VERSION = '0.1'
DESCRIPTION = 'Attacking using IPython & Impacket'
LONG_DESCRIPTION = 'a tool which allows red teams to attack computers via IPython shell'

setup(
    name="mosK",
    version=VERSION,
    author_email="<vikbarel5@gmail.com>",
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=LONG_DESCRIPTION,
    packages=find_packages(),
    install_requires=[],
    keywords=['python', 'red team', 'attack', 'impacket', 'cyber'],
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
    ]
)