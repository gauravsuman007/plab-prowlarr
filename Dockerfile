# Stage 1 — compile the proxy against Alpine musl and stage the full overlay in /out
FROM public.ecr.aws/docker/library/alpine:3.20 AS builder
RUN apk add --no-cache gcc musl-dev curl-dev sqlite-dev sqlite-static
COPY proxy.c /src/proxy.c
# SQLite is linked in statically: the sidecar reads Prowlarr's database (its saved PornoLab session) and
# must not depend on which libsqlite3 the host container happens to ship.
RUN gcc -O2 -o /torrent-proxy /src/proxy.c -lcurl -lpthread /usr/lib/libsqlite3.a -lm && strip /torrent-proxy
COPY rootfs/ /out/
COPY pornolab-noquota.yml /out/torrent-proxy/pornolab-noquota.yml
RUN mkdir -p /out/usr/local/bin && cp /torrent-proxy /out/usr/local/bin/torrent-proxy

# Stage 2 — the linuxserver mod installer extracts ONLY layers[0], so the whole overlay must be a single COPY
FROM scratch
COPY --from=builder /out/ /
