FROM --platform=linux/amd64 python:3.9 AS x86_64_image

LABEL authors="Osamuede Obasuyi"
LABEL description="This image contains a portable version of ColdClarity."
LABEL version="1.0"
LABEL license="GPL"


COPY ./* ColdClarity/
WORKDIR ColdClarity

RUN pip install -r requirements.txt


CMD ["python3.9", "./term_access.py", "--config_file", "config.yaml"]