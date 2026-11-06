FROM alpine:3.23
RUN apk add --no-cache iptables iptables-legacy iproute2 ca-certificates
COPY synovpn charon /opt/synovpn/
ENV SYNOVPN_ENGINE_CONTAINER=1
ENTRYPOINT ["/opt/synovpn/synovpn", "engine"]
