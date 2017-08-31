FROM python:2.7.13

RUN mkdir -p /usr/src/app
COPY . /usr/src/app
WORKDIR /usr/src/app
RUN pip install .
ENV AWS_DIR /aws

ENTRYPOINT [ "python", "-msamlkeygen" ]
CMD [ "--help" ]
