# syntax=docker/dockerfile:1
FROM python:3.10-alpine
WORKDIR /code
COPY ./src/ ./
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

CMD ["fastapi", "run", "./main.py", "--port", "8000"]