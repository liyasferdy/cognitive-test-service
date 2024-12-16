# Gunakan image dasar Python yang ringan
FROM python:3.11-slim

# Buat direktori kerja
WORKDIR /app

# Salin file requirements.txt terlebih dahulu untuk caching layer instalasi
COPY requirements.txt /app/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Salin seluruh kode ke dalam image
COPY . /app/

# (Opsional) Jika Anda ingin menggunakan variabel environment dari file .env, 
# Anda bisa mengaturnya lewat docker-compose atau docker run -e KEY=VALUE
# Pastikan file .env tidak disalin ke dalam image jika mengandung informasi sensitif.

# Ekspose port jika aplikasi perlu diakses dari luar
EXPOSE 8080

# Jalankan aplikasi
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
