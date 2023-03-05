FROM orgoro/dlib-opencv-python:latest AS dlib

FROM python:3.7

COPY --from=dlib /usr/local/lib/python3.7/site-packages/dlib /../usr/local/lib/python3.7/site-packages/dlib

WORKDIR /code

COPY ./requirements.txt /code/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY ./app /code/app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]