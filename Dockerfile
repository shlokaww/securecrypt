FROM python:3.12-slim
WORKDIR /app
RUN adduser --disabled-password --gecos '' securecrypt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p uploads outputs && chown -R securecrypt:securecrypt /app
USER securecrypt
EXPOSE 5000
ENV PORT=5000
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-5000} --workers ${WEB_CONCURRENCY:-2} 'app:create_app()'"]
