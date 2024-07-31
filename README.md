# FHERMA-Challenge

### Setup Instructions

1. Clone this repo and navigate to FHERMA-Challenge folder
    ```
    git clone https://github.com/AryanTII/FHERMA-Challenge.git
    cd FHERMA-Challenge
    ```
    **IMPORTANT**: (Development) Make sure to checkout to the correct branch; we usually have the ongoing task in the `development` branch:
    ```
    git checkout development
    ```

2. Clone OpenFHE Repositories inside the FHERMA-Challenge folder
    ```
    git clone https://github.com/openfheorg/openfhe-development.git
    git clone https://github.com/openfheorg/openfhe-python.git
    ```

3. Docker compose
    ```
    docker-compose up
    ```

4. Navigate to the respective challenge folder (e.g. `array_sort`) in the shell of the above created docker container:
    ```
    cd array_sort
    ```

4. Run the below command (example folder within docker container shell):
    ```
    ./run.sh 
    ```
    **IMPORTANT**: (First time Setup) To generate the keys and input files for local testing, run the following:
    ```
    ./run.sh 1
    ```
