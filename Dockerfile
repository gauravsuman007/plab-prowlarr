# Stage 1 — compile the proxy against Alpine musl
FROM public.ecr.aws/docker/library/alpine:3.20 AS builder
RUN apk add --no-cache gcc musl-dev curl-dev
COPY proxy.c /src/proxy.c
RUN gcc -O2 -o /torrent-proxy /src/proxy.c -lcurl -lpthread && strip /torrent-proxy

# Stage 2 — mod image based on linuxserver Alpine so the mod installer can extract layers
FROM ghcr.io/linuxserver/baseimage-alpine:3.20
RUN apk add --no-cache libcurl
COPY --from=builder /torrent-proxy              /usr/local/bin/torrent-proxy
COPY rootfs/                                     /
COPY pornolab-noquota.yml                        /torrent-proxy/pornolab-noquota.yml
