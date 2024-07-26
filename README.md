# FHERMA-Challenge

### Setup Instructions

1. Clone OpenFHE Repositories inside the FHERMA-Challenge folder
    ```
    git clone https://github.com/openfheorg/openfhe-development.git
    git clone https://github.com/openfheorg/openfhe-python.git
    ```
2. Docker compose
    ```
    docker-compose up
    ```
3. Run the below command in the shell of the above created docker container:
    ```
    export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
    mkdir build
    ./run.sh
    ```
