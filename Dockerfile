# Stage 1 — compile the proxy against Alpine musl
FROM public.ecr.aws/docker/library/alpine:3.20 AS builder
RUN apk add --no-cache gcc musl-dev curl-dev
COPY proxy.c /src/proxy.c
RUN gcc -O2 -o /torrent-proxy /src/proxy.c -lcurl -lpthread && strip /torrent-proxy

# Stage 2 — minimal mod image (overlaid onto the Prowlarr container by linuxserver)
# FROM scratch keeps the image tiny; linuxserver's Alpine base already has libcurl deps.
FROM scratch
COPY --from=builder /torrent-proxy              /usr/local/bin/torrent-proxy
COPY --from=builder /usr/lib/libcurl.so.4       /usr/lib/libcurl.so.4
COPY rootfs/                                     /
COPY pornolab-noquota.yml                        /torrent-proxy/pornolab-noquota.yml
