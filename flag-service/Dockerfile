FROM python:3.12-slim

WORKDIR /app
COPY app.py stage1.py stage2.py stage3.py ./

ENV PORT=8080
ENV STAGE=all
EXPOSE 8080

CMD ["python", "app.py"]

