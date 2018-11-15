FROM python:3.6

ENV PYTHONUNBUFFERED 1

RUN mkdir /code

WORKDIR /code

ADD requirements.txt /code/
RUN pip install --no-cache-dir -r requirements.txt

ADD deploy.py /code/
ADD deploy_linked.py /code/

ENTRYPOINT python /code/deploy_linked.py /code/hub.json ${CONTRACT_HASH} ${RPC} --publish && python /code/deploy.py /code/token.bc ${CONTRACT_HASH} ${RPC} --publish && yes
