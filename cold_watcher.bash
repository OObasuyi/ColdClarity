#!/bin/bash

# made for RHEL PODMAN but can be switched for DOCKER
IMAGE_NAME="coldclarity"
CONTAINER_NAME="ColdClaritySVCS_$RANDOM"
CONFIG_LOCATION="/path/to/config"
CERT_PFX_LOCATION="PATH/TO/CERT"
MAX_RETRIES=3
RETRIES=0

# IF YOU DONT USE CERT DROP "-v "$CERT_PFX_LOCATION":/ColdClarity/certificate_information/ise_client_cert.pfx:Z" from the command line
start_container() {
    podman run -d -v "$CONFIG_LOCATION":/ColdClarity/Config_information/config.yaml:Z -v "$CERT_PFX_LOCATION":/ColdClarity/certificate_information/ise_client_cert.pfx:Z --name "$CONTAINER_NAME" "$IMAGE_NAME"
}

cleanup_containers() {
    podman rm "$CONTAINER_NAME"
    echo "Removed STOPPED $CONTAINER_NAME"
}

# Trap exit signal to ensure cleanup even on script interruption
trap cleanup_containers EXIT

while true; do
    start_container

     # Wait for the container to exit
    podman wait "$CONTAINER_NAME"

    # Get the exit status of the container
    container_status=$(podman inspect -f "{{.State.ExitCode}}" "$CONTAINER_NAME")

    # Check if the container exited gracefully (with an exit status of 0)
    if [ "$container_status" -eq 0 ]; then
        echo "ColdClarity has completed"
        break
    else
        # The container failed to start
        echo "ColdClarity exited with an error (Exit Status: $container_status)."

        # Increment the retry counter
        RETRIES=$((RETRIES + 1))

        # Check if we've exceeded the maximum number of retries
        if [ $RETRIES -ge $MAX_RETRIES ]; then
            echo "Maximum number of retries reached. Exiting."
            exit 1
        else
            echo "Retrying (Attempt $RETRIES)..."
            sleep 5
        fi
    fi
done
