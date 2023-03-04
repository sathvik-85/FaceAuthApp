FROM python:3.7
 
WORKDIR /code


RUN apt-get update && \
    apt-get install -y build-essential cmake && \
    apt-get clean && rm -rf /var/lib/apt/lists/* 


RUN pip install dlib
 
COPY ./requirements.txt /code/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt
 
COPY ./app /code/app


CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
