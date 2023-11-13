#!/bin/bash

# made for RHEL PODMAN but can be switched for DOCKER
IMAGE_NAME="coldclarity"
CONTAINER_NAME="ColdClaritySVCS_$RANDOM"
CONFIG_LOCATION="/path/to/config"
CERT_PFX_LOCATION="PATH/TO/CERT"
WORKING_DIR="/opt/$IMAGE_NAME"
LOGGING_FILE="$WORKING_DIR/logs/$IMAGE_NAME.log"
MAX_RETRIES=4
RETRIES=0

# Script should run from the /OPT directory; configs can be anywhere
# IF YOU DONT USE CERT DROP "-v "$CERT_PFX_LOCATION":/ColdClarity/certificate_information/ise_client_cert.pfx:Z" from the command line

# Check or create logging Dir and file
if [ ! -d "$WORKING_DIR/logs" ]; then
    # If the directory doesn't exist, create it
    mkdir -p "$WORKING_DIR/logs"
    echo "$(date): $WORKING_DIR/logs created." >> "$LOGGING_FILE"
else
    echo "$(date): $WORKING_DIR/logs already exists." >> "$LOGGING_FILE"
fi


start_container() {
    podman run -it --privileged -v "$CONFIG_LOCATION":/ColdClarity/Config_information/config.yaml:Z -v "$CERT_PFX_LOCATION":/ColdClarity/certificate_information/ise_client_cert.pfx:Z --name "$CONTAINER_NAME" "$IMAGE_NAME"
}

cleanup_containers() {
    podman rm -f "$CONTAINER_NAME"
    echo "$(date): Cleaning up and removing used $CONTAINER_NAME" >> "$LOGGING_FILE"
}

# Trap exit signal to ensure cleanup even on script interruption
trap cleanup_containers EXIT

while true; do
    # start container
    init_container=$(start_container)
    echo "$(date): INFO: $init_container" >> "$LOGGING_FILE"


    # check to make sure the container really started
    container_started=$(podman ps -a | grep $CONTAINER_NAME)


     # Wait for the container to exit
    podman wait "$CONTAINER_NAME"

    # Get the exit status of the container
    container_status=$(podman inspect -f "{{.State.ExitCode}}" "$CONTAINER_NAME")



    if [[ $container_started == *"$CONTAINER_NAME"* ]]; then
          echo "$(date): $CONTAINER_NAME started successfully" >> "$LOGGING_FILE"

          # Check if the container exited gracefully (with an exit status of 0)
          if [ "$container_status" -eq 0 ]; then
              echo "$(date): ColdClarity has completed" >> "$LOGGING_FILE"
              break
          else
                 # if we failed because the container started but problem is from app
                 echo "$(date): ERROR: ColdClarity did not execute properly (Exit Status: $container_status)." >> "$LOGGING_FILE"

                 # Increment the retry counter
                 RETRIES=$((RETRIES + 1))

                # Check if we've exceeded the maximum number of retries
                if [ $RETRIES -ge $MAX_RETRIES ]; then
                    echo "$(date): ERROR: Maximum number of retries reached. Exiting." >> "$LOGGING_FILE"
                    exit 1
                else
                    echo "$(date): ERROR: Retrying (Attempt $RETRIES)..." >> "$LOGGING_FILE"
                    sleep 5
                fi
          fi
    else
       echo "$(date): ERROR Container failed to start" >> "$LOGGING_FILE"
       # Increment the retry counter
       RETRIES=$((RETRIES + 1))

      # Check if we've exceeded the maximum number of retries
      if [ $RETRIES -ge $MAX_RETRIES ]; then
          echo "$(date): ERROR: Maximum number of retries reached. Exiting." >> "$LOGGING_FILE"
          exit 1
      else
          echo "$(date): Retrying (Attempt $RETRIES)..." >> "$LOGGING_FILE"
          sleep 5
      fi

    fi
done


