FROM python:2.7.13

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /usr/src/app

ENTRYPOINT [ "python", "./samlapi.py", "authenticate" ]
CMD [ "--help" ]