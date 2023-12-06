from setuptools import setup

# because the python ecosystem is stupid.
with open("requirements.txt") as f:
    requirements = f.read().splitlines()

setup(
   name='ashnazg',
   version='1.0',
   description='And in the darkness bind them',
   author_email='archgoon+ashnazg@gmail.com',
   packages=['ashnazg', 'ashnazg.analyses', "ashnazg.simprocedures"],  #same as name
   scripts=["bin/ashnazg"],
   install_requires = ["smrop", "dorat"],
   dependency_links = requirements
)
