FROM alpine:3.8

RUN apk --update add --no-cache python3=3.6.6-r0 bash libffi openssl

COPY . /usr/src/app
WORKDIR /usr/src/app

RUN apk --update add --no-cache --virtual .build-deps \
    python3-dev=3.6.6-r0 gcc musl-dev libffi-dev openssl-dev && \
    python3 -m ensurepip && \
    pip3 --no-cache-dir install --upgrade pip setuptools && \
    pip3 --no-cache-dir install . && \
    apk --update del --no-cache .build-deps && \
    python3 -m pip uninstall --yes pip setuptools

ENV AWS_DIR /aws

ENTRYPOINT [ "python3", "-msamlkeygen" ]
CMD [ "--help" ]
