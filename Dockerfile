#     https://hub.docker.com/_/python/tags?page=1&ordering=-name&name=2-alpine
FROM  python:2-alpine
LABEL maintainer="realizelol"                                           \
      name="realizelol/unraid-libvirt-wol"                              \
      description="Docker for wake up vms via libvirt on unraid host."  \
      version="0.1"                                                     \
      url="https://hub.docker.com/r/realizelol/unraid-libvirt-wol"      \
      vcs-url="https://github.com/realizelol/docker-unraid-libvirt-wol" \
      vcs-ref=$VCS_REF                                                  \
      build-date=$BUILD_DATE

RUN rm -rf /var/cache/apk/*                                                                                                                                &&  \
    apk upgrade --latest --update-cache                                                                                                                    &&  \
    apk add --update-cache py-pip libvirt-dev libxml2-dev libpcap-dev curl                                                                                 &&  \
    rm -rf /root/.cache /var/cache/apk/*                                                                                                                   &&  \
    curl -sL https://raw.githubusercontent.com/dmacias72/unRAID-libvirtwol/master/source/libvirtwol/usr/local/emhttp/plugins/libvirtwol/scripts/libvirtwol.py  \
      > /app/libvirt.py                                                                                                                                    &&  \
    curl -sL https://raw.githubusercontent.com/dmacias72/unRAID-libvirtwol/master/source/libvirtwol/usr/local/emhttp/plugins/libvirtwol/scripts/lvwolutils.py  \
      > /app/lvwolutils.py                                                                                                                                 &&  \
#    curl -sL https://raw.githubusercontent.com/dmacias72/unRAID-libvirtwol/master/source/libvirtwol/usr/local/emhttp/plugins/libvirtwol/scripts/lvwolutils.pyc \
#      > /app/lvwolutils.pyc

WORKDIR /app
COPY .  /app

# volumes
VOLUME ["/var/run/libvirt/libvirt-sock"]

# listen to port 9/udp
EXPOSE 9/udp

# entrypoint - always keep everything up2date
ENTRYPOINT ["apk upgrade", "--latest", "--update-cache"]

CMD ["/usr/bin/python", "/app/libvirt.py", "br0"]
