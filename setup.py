from setuptools import setup

setup(
   name='ashnazg',
   version='1.0',
   description='And in the darkness bind them',
   author_email='archgoon+ashnazg@gmail.com',
   packages=['ashnazg', 'ashnazg.analyses'],  #same as name
   install_requires=[], #external packages as dependencies
   scripts=["bin/ashnazg"]
)
