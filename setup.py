from setuptools import setup
import codecs
import os.path
import subprocess


# because the python ecosystem is stupid.
with open("requirements.txt") as f:
    requirements = f.read().splitlines()

def read(rel_path):
    here = os.path.abspath(os.path.dirname(__file__))
    with codecs.open(os.path.join(here, rel_path), 'r') as fp:
        return fp.read()

def get_version(rel_path):
    for line in read(rel_path).splitlines():
        if line.startswith('__version__'):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    else:
        raise RuntimeError("Unable to find version string.")

def set_version(rel_path):
    path = os.path.join(os.path.abspath(os.path.dirname(__file__)), rel_path)
    result = subprocess.check_output(["git","rev-parse","HEAD"]).strip().decode("ascii")
    with open(path, "w") as version_file:
        version_file.write(f"__version__='{result}'")
    return result

setup(
   name='ashnazg',
   version=set_version("ashnazg/version.py"),
   description='And in the darkness bind them',
   author_email='archgoon+ashnazg@gmail.com',
   packages=['ashnazg', 'ashnazg.analyses'],  #same as name
   scripts=["bin/ashnazg"],
   install_requires = ["smrop", "dorat"],
   dependency_links = requirements
)
