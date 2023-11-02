# FROM alpine:latest
# FROM busybox:latest
FROM scratch

# --build-arg PACKAGE_NAME=${package_name}
ARG PACKAGE_NAME="q-api-auth"
ARG TARGET="x86_64-unknown-linux-musl"

COPY ./target/${TARGET}/release/${PACKAGE_NAME} /bin/${PACKAGE_NAME}
COPY ./Rocket.toml /

# WORKDIR /
CMD [ "q-api-auth" ]
