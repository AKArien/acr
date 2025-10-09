FROM python:3.14.0rc3-slim-trixie

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

RUN ln -s cronjob-run-populate /etc/cron.d/run-populate

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
