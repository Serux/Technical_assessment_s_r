# syntax=docker/dockerfile:1
FROM python:3.10-alpine
WORKDIR /code
## We install first the requirements for them to be cached by Docker and not to be re-downloaded
COPY ./src/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt
 
COPY ./src/main.py ./main.py

CMD ["fastapi", "run", "./main.py", "--port", "8000"]