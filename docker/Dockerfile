FROM alpine:3.17 AS build-env

RUN apk add --update autoconf automake libtool git make gcc zlib g++

COPY . src/

RUN cd src \
  && make \
  && make install

FROM alpine:3.17

COPY --from=build-env /usr/local/bin /usr/local/bin

WORKDIR /

ENTRYPOINT ["/usr/local/bin/nostril"]