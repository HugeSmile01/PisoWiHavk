# Use an appropriate base image
FROM ubuntu:latest

# Install required packages
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    jq \
    netcat-openbsd \
    ipcalc \
    coreutils \
    grep \
    sed \
    gawk \
    sudo \
    arp-scan \
    macchanger \
    hydra \
    python3 \
    python3-pip \
    tcpdump \
    wireshark \
    aircrack-ng \
    ettercap-text-only \
    john \
    hashcat

# Install Python requests library
RUN pip3 install --upgrade requests --break-system-packages

# Copy project files into the Docker container
COPY . /app

# Set the working directory
WORKDIR /app

# Add a script to check for the presence of required packages and install them if missing
COPY PisoWiHavk_Version2.sh /usr/local/bin/check_and_install_pkg.sh
RUN chmod +x /usr/local/bin/check_and_install_pkg.sh

# Set the entry point to run the main script
ENTRYPOINT ["/usr/local/bin/check_and_install_pkg.sh"]
