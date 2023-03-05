

FROM python:3.7


COPY --from=orgoro/dlib-opencv-python:latest /usr/local/lib/python3.7/site-packages /usr/local/lib/python3.7/site-packages
COPY --from=orgoro/dlib-opencv-python:latest /usr/local/include/dlib /usr/local/include/dlib
COPY --from=orgoro/dlib-opencv-python:latest /usr/local/lib/libdlib.so* /usr/local/lib/
COPY --from=orgoro/dlib-opencv-python:latest /usr/local/lib/libopencv* /usr/local/lib/
ENV PYTHONPATH=$PYTHONPATH:/usr/local/lib/python3.7/site-packages

RUN mkdir /code

WORKDIR /code

COPY ./requirements.txt /code/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY ./app /code/app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]