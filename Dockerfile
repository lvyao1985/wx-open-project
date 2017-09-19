FROM python:2.7

WORKDIR /app

COPY localtime /etc/localtime
COPY requirements.txt /app
RUN mkdir ~/.pip
RUN echo "[global]\nindex-url=http://pypi.douban.com/simple\n[install]\ntrusted-host=pypi.douban.com" > ~/.pip/pip.conf
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

EXPOSE 80

CMD ["gunicorn", "run:app", "-b", "0.0.0.0:80", "--log-file", "-", "--access-logfile", "-"]
