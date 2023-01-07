#!/bin/bash
set -e


# update packages in background if connected to www
( ( while ! ping -c3 -W3 alpinelinux.org; do sleep 2; done; \
    apk upgrade --latest --update-cache \
)& )>/dev/null 2>&1

# run python2
echo "$(date +'%Y-%m-%d - %H:%M:%S') - libvirtwol started successfully."
exec "${@}"
