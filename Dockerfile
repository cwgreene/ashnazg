FROM ubuntu:22.04
# Install program requirements
RUN apt update
RUN apt install -y python3 python3-pip
RUN apt install -y git
RUN apt install -y zip curl openjdk-21-jdk

# Mkdir
RUN mkdir -p /home/ashnazg

# Get requirements in as soon as possible since they'll take a while to install
# and we don't want to do this as much as possible.
WORKDIR /home/ashnazg
ADD requirements.txt /home/ashnazg 
RUN pip3 install -r requirements.txt

# get dorat fully installed
RUN dorat --install-ghidra --ghidra-install-dir=/home/ghidra --ghidra-scripts-install-dir=/home/ghidrascripts
COPY Docker.dorat.json /root/.config/github.com/cwgreene/dorat/dorat.json

# Copy ashnazg itself
ADD setup.py pyproject.toml /home/ashnazg
ADD bin/ /home/ashnazg/bin
ADD test/ /home/ashnazg/test
ADD test_data/ /home/ashnazg/test_data
ADD ashnazg/ /home/ashnazg/ashnazg

# install it
RUN pip3 install .
# Fix up the lldb madness here
