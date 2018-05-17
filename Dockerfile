FROM alpine:3.7

RUN apk --update add --no-cache python=2.7.14-r2 bash libffi openssl

COPY . /usr/src/app
WORKDIR /usr/src/app

RUN apk --update add --no-cache --virtual .build-deps \
    python2-dev=2.7.14-r2 gcc musl-dev libffi-dev openssl-dev && \
    python -m ensurepip && \
    pip --no-cache-dir install --upgrade pip setuptools && \
    pip --no-cache-dir install . && \
    apk --update del --no-cache .build-deps && \
    python -m pip uninstall --yes pip setuptools

ENV AWS_DIR /aws

ENTRYPOINT [ "python", "-msamlkeygen" ]
CMD [ "--help" ]
