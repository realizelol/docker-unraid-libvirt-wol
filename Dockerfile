#     https://hub.docker.com/_/python/tags?page=1&ordering=-name&name=2-alpine
FROM  python:2-alpine
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
    apk add --update-cache libvirt-dev libxml2-dev libpcap-dev python-dev libffi-dev build-base curl                                                        &&  \
    pip install --upgrade pip --no-cache-dir                                                                                                                &&  \
    pip install --upgrade Cython pycparser cffi libpcap==1.10.0b5 libvirt-python==5.10.0 pypcap --no-cache-dir                                              &&  \
    pip cache purge                                                                                                                                         &&  \
    rm -rf /root/.cache /var/cache/apk/*

# volumes
VOLUME ["/var/run/libvirt/libvirt-sock"]

# listen to port 9/udp
EXPOSE 9/udp

# entrypoint - always keep everything up2date and then start libvirtwol.py
ENTRYPOINT /app/docker-entrypoint.sh python2 /app/libvirtwol.py enp0s17
