#     https://hub.docker.com/_/python/tags?page=1&ordering=-name&name=2-alpine
FROM  python:3-alpine
LABEL maintainer="realizelol"                                                                                                                                   \
      name="realizelol/unraid-libvirt-wol"                                                                                                                      \
      description="Docker for wake up vms via libvirt on unraid host."                                                                                          \
      version="0.1"                                                                                                                                             \
      url="https://hub.docker.com/r/realizelol/unraid-libvirt-wol"                                                                                              \
      vcs-url="https://github.com/realizelol/docker-unraid-libvirt-wol"                                                                                         \
      vcs-ref=$VCS_REF                                                                                                                                          \
      build-date=$BUILD_DATE

# copy "app" content to container's /app
COPY ./app /app

# install needed packages etc.
RUN rm -rf /var/cache/apk/*                                                                                                                                 &&  \
    apk upgrade --latest --update-cache                                                                                                                     &&  \
    apk add --update-cache libvirt libvirt-dev py3-libvirt libxml2-dev python3-dev libffi-dev libpcap libpcap-dev build-base bash                           &&  \
    pip install --upgrade pip --no-cache-dir                                                                                                                &&  \
    pip install --upgrade Cython --install-option="--no-cython-compile" --no-cache-dir                                                                      &&  \
    pip install --upgrade pycparser cffi pcap-ct python-libpcap libvirt-python --no-cache-dir                                                               &&  \
    apk del build-base                                                                                                                                      &&  \
    pip cache purge                                                                                                                                         &&  \
    rm -rf /root/.cache /var/cache/apk/*                                                                                                                    &&  \
    chmod +x /app/*.py /app/*.sh                                                                                                                            &&  \
    mkdir -p /var/log/libvirt

# volumes
VOLUME ["/var/run/libvirt/libvirt-sock"]

# listen to port 9/udp
EXPOSE 9/udp

# entrypoint - always keep everything up2date and then start libvirtwol.py
ENTRYPOINT /app/docker-entrypoint.sh python3 /app/libvirtwol.py enp0s17
