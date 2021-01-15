FROM python:3.7-alpine
WORKDIR /var/www

ENV FLASK_APP app/app.py
ENV FLASK_RUN_HOST 0.0.0.0
ENV FLASK_ENV development

RUN apk add --no-cache gcc musl-dev linux-headers openssl-dev libffi-dev
COPY uwsgi.ini uwsgi.ini
COPY wsgi.py wsgi.py
COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt
COPY app app
CMD ["uwsgi", "--ini", "uwsgi.ini"]

RUN chown -R nobody:nobody app
