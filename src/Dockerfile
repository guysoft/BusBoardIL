FROM tiangolo/uwsgi-nginx-flask:python3.6-alpine3.7
MAINTAINER Guy Sheffer <guysoft at gmail dot com>

EXPOSE 80

COPY ./app /app
COPY ./app/config.ini.docker /app/config.ini
COPY ./requirements.txt /requirements.txt

RUN wget https://bootstrap.pypa.io/get-pip.py -O - | python3
RUN pip3 install -r /requirements.txt
