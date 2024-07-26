# Use a base image with Ubuntu (or your preferred base image)
FROM ubuntu:20.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV NO_THREADS=4
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Update and install necessary packages
RUN apt-get update && \
    apt-get install -y \
    git \
    build-essential \
    gcc \
    g++ \
    cmake \
    autoconf \
    clang \
    libomp5 \
    python3 \
    python3-pip \
    libomp-dev \
    doxygen \
    graphviz \
    libboost-all-dev && \
    # Install Python packages
    pip3 install --no-cache-dir "pybind11[global]" numpy && \
    # Disable SSL verification for git if necessary
    git config --global http.sslverify "false"

# Set the working directory
WORKDIR /workspace

# Copy your local OpenFHE source code into the Docker image
COPY openfhe-development /workspace/openfhe-development
COPY openfhe-python /workspace/openfhe-python

# Build OpenFHE
WORKDIR /workspace/openfhe-development
RUN mkdir -p build && cd build && \
    cmake .. && \
    make -j$(nproc) && \
    make install

# Build OpenFHE Python
WORKDIR /workspace/openfhe-python
RUN mkdir -p build && cd build && \
    cmake .. && \
    make -j$(nproc) && \
    make install

# Set the working directory
WORKDIR /workspace

# Set the default command (you can replace this with any other command you want to run)
CMD ["bash"]
