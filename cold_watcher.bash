#!/bin/bash

# made for RHEL PODMAN but can be switched for DOCKER
CONTAINER_NAME="coldclarity"
CONFIG_LOCATION="/path/to/config"
CERT_PFX_LOCATION="PATH/TO/CERT"
MAX_RETRIES=3
RETRIES=0

# IF YOU DONT USE CERT DROP "-v "$CERT_PFX_LOCATION":/ColdClarity/certificate_information/ise_client_cert.pfx:Z" from the command line
start_container() {
    podman run -it -v "$CONFIG_LOCATION":/ColdClarity/Config_information/config.yaml:Z -v "$CERT_PFX_LOCATION":/ColdClarity/certificate_information/ise_client_cert.pfx:Z "$CONTAINER_NAME"
}

cleanup_containers() {
    # List ColdClarity containers, including stopped ones
    container_list=$(podman ps -a --filter "ancestor=$CONTAINER_NAME" --filter "status=exited" -q)

    if [ -n "$container_list" ]; then
        # Remove all stopped containers
        podman rm "$container_list"
        echo "Removed STOPPED $IMAGE_NAME containers"
    fi
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