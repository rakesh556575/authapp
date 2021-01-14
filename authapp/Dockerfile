FROM alpine:3.11.6
FROM python:3.8.3-alpine

ADD . /authser

WORKDIR /authser

RUN pip install -r requirements.txt
RUN ls -la
CMD ["python","manage.py","makemigrations"]
CMD ["python","manage.py","migrate"]
CMD ["python","manage.py", "runserver", "0.0.0.0:3000"]