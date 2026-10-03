FROM python:3.12-slim

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

# Set a real flag at run time, e.g.:
#   docker run -e FLAG='CTF{your_flag_here}' -p 5000:5000 taskhub
ENV FLAG="CTF{m1ss1ng_func7ion_lvl_4cc3ss_c0ntr0l}"

EXPOSE 5000
CMD ["python", "app.py"]
