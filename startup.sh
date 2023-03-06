#!/bin/bash
sudo yum install -y git
sudo yum install -y nginx
sudo yum install -y nodejs  
npm -v
sudo systemctl enable nginx
sudo systemctl start nginx
git clone https://github.com/cloudacademy/static-website-example.git

sudo systemctl enable nginx
sudo systemctl start nginx
sudo rm -rf *.html
mv ./static-website-example/* /usr/share/nginx/html
