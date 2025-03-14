FROM ubuntu:latest

# Enable the Universe repository and install required packages
RUN apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository universe && \
    apt-get update && \
    apt-get install -y \
        openssh-server \
        iproute2 \
        iw \
        net-tools \
        hostapd \
        wpasupplicant \
        sudo \
        build-essential \
        git \
        pkg-config \
        libssl-dev \
        libnl-3-dev \
        libnl-genl-3-dev \
        autoconf \
        automake \
        libtool \
        ethtool \
        usbutils \
        pciutils \
        vim

# Compile and install aircrack-ng from source
RUN git clone https://github.com/aircrack-ng/aircrack-ng.git /tmp/aircrack-ng && \
    cd /tmp/aircrack-ng && \
    autoreconf -i && \
    ./configure --disable-opencl && \
    make && \
    make install && \
    ldconfig && \
    rm -rf /tmp/aircrack-ng

# Create SSH runtime directory
RUN mkdir /var/run/sshd

# Create a new user 'ctf-user' with a home directory and bash shell and grant passwordless sudo
RUN useradd -m -s /bin/bash ctf-user && \
    echo 'ctf-user:ctf' | chpasswd && \
    usermod -aG sudo ctf-user && \
    echo "ctf-user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Configure SSH
RUN sed -i 's/PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "AllowUsers ctf-user" >> /etc/ssh/sshd_config

# Copy configuration files for hostapd and wpa_supplicant
COPY wpa-psk.conf /etc/hostapd/wpa-psk.conf
COPY wpa_supplicant_wpa.conf /etc/wpa_supplicant_wpa.conf

# Copy the updated in-container configuration script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
