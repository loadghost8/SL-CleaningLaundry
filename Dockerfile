FROM python:3.10-slim
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
WORKDIR /app
# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    libjpeg-dev \
    zlib1g-dev \
    libpng-dev \
    libfreetype6-dev \
    libopenjp2-7-dev \
    libopencv-dev \
    libopencv-contrib-dev \
    libavcodec-dev \
    libavformat-dev \
    libswscale-dev \
    libv4l-dev \
    gfortran \
    libatlas-base-dev \
    libfontconfig1-dev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir numpy==2.2.4 scipy==1.15.2 opencv-python==4.11.0.86
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:$PORT"]