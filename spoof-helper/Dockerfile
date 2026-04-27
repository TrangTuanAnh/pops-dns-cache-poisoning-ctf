FROM python:3.12-slim

WORKDIR /app
COPY app.py .

ENV PORT=8080
ENV SPOOF_HELPER_DRY_RUN=true
EXPOSE 8080

CMD ["python", "app.py"]

