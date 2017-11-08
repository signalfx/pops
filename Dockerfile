FROM scratch
COPY ca-bundle.crt /etc/pki/tls/certs/ca-bundle.crt
COPY ./output/linux/pops /pops
# COPY ./buildInfo.json /buildInfo.json
CMD ["/pops"]