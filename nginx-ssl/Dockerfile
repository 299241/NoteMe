FROM nginx
COPY nginx.conf /etc/nginx/nginx.conf
COPY server.company.com.crt /etc/nginx/server.company.com.crt
COPY server.company.com.key /etc/nginx/server.company.com.key
COPY server.company.com.pass /etc/nginx/server.company.com.pass

RUN apt-get update && apt-get install -y -o Dpkg::Options::="--force-confold" passenger nginx-extras
