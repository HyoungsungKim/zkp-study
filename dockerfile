FROM python:3.8-bullseye

RUN apt-get update && apt-get install build-essential -y
RUN apt-get install git

# Python 패키지 업데이트 및 Jupyter 설치
RUN pip install --upgrade pip
RUN pip install jupyterlab