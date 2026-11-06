# syntax=docker/dockerfile:1
FROM alpine:3.23 AS build
RUN apk add --no-cache build-base linux-headers openssl-dev openssl-libs-static zlib-dev zlib-static python3 file curl
WORKDIR /src
RUN curl --fail --location --proto '=https' --tlsv1.2 https://download.strongswan.org/strongswan-6.1.0.tar.gz -o strongswan-6.1.0.tar.gz \
 && echo 'd9484eea319481bda86f992fa69cbdbdd9c0d6f8b9a4bd793a7df45c0760d963  strongswan-6.1.0.tar.gz' | sha256sum -c - \
 && tar xzf strongswan-6.1.0.tar.gz
WORKDIR /src/strongswan-6.1.0
COPY tools/disable-udp-gro.py tools/check-static-elf.py /src/
RUN python3 /src/disable-udp-gro.py .
RUN ./configure --prefix=/synovpn --with-piddir=/var/packages/SynoVPN/var/run \
    --disable-defaults --disable-shared --enable-static --enable-monolithic \
    --enable-charon --enable-ikev2 --enable-kernel-netlink --enable-socket-default \
    --enable-vici --enable-openssl --enable-aes --enable-sha1 --enable-sha2 \
    --enable-hmac --enable-random --enable-nonce --enable-x509 --enable-revocation \
    --enable-constraints --enable-pubkey --enable-pkcs1 --enable-pkcs8 --enable-pem \
    --enable-drbg \
 && make -j2 LDFLAGS='-all-static' \
 && make install \
 && python3 /src/check-static-elf.py /synovpn/libexec/ipsec/charon
RUN mkdir -p /out/licenses /out/source \
 && cp /synovpn/libexec/ipsec/charon /out/charon \
 && cp COPYING LICENSE /out/licenses/ \
 && cp /src/strongswan-6.1.0.tar.gz /src/disable-udp-gro.py /out/source/ \
 && if [ -d /usr/share/licenses ]; then cp -r /usr/share/licenses/. /out/licenses/alpine-build-dependencies; fi

FROM build AS smoke
ARG PROBE=build/vici-probe-linux-amd64
COPY ${PROBE} /probe
COPY tools/runtime-smoke.sh /smoke.sh
ENTRYPOINT ["/bin/sh", "/smoke.sh"]

FROM scratch AS runtime
COPY --from=build /out/ /
