# ModSecurity + Nginx (step-by-step)



### Prerequisites - install packages

Run (example for Debian/Ubuntu). I added commonly required packages:

```shell
sudo apt install git
sudo apt install libxslt-dev
sudo apt install libgd-dev
sudo apt install libssl-dev
sudo apt install libperl-dev
sudo apt install libtool pkg-config
sudo apt install libpcre2-dev
sudo apt install libtajl-dev
sudo apt install libgeoip-dev
sudo apt install libmaxminddb-dev
sudo apt install liblmdb-dev
sudo apt install libfuzzy-dev
sudo apt install liblua5.3-dev
sudo apt install libcurl4-dev
sudo apt install libxml2-dev
sudo apt install pkg-config
sudo apt install build-essential
```

----
### STEPS
#### 1- Clone ModSecurity and ModSecurity-nginx
	
```shell
sudo git clone https://github.com/owasp-modsecurity/ModSecurity.git
sudo git clone https://github.com/owasp-modsecurity/ModSecurity-nginx.git
wget http://nginx.org/download/nginx-1.28.0.tar.gz
tar xf nginx-1.28.0.tar.gz
```

---
#### 2- Create a vulnerable php website

`sudo nano /var/www/html/index.php`

```php
<?php
$q = isset($_GET['q']) ? $_GET['q'] : '';
?>
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Reflected XSS demo</title></head>
<body>
  <h2>Reflected XSS demo</h2>
  <form method="get">
    <input name="q" value="<?php echo htmlspecialchars($q, ENT_QUOTES); ?>" />
    <button type="submit">Search</button>
  </form>

  <div>
    <h3>Search results for: </h3>
    <!-- vulnerable output (intentionally not escaped) -->
    <div><?php echo $q; ?></div>
  </div>
</body>
</html>

```

<p align ="center">
    <img src= "/projects/ModSec_Nginx/photo/2-create_phpfile.png"
</p>

**Then configure Nginx to serve PHP**

`sudo nano /etc/nginx/sites-available/default`

***Note: in the location line ensure to write the exact version of your php***

```
server { 
	listen 80; 
	
	server_name your_server_domain_or_IP; 
	root /var/www/html;
	index index.php index.html index.htm; 
	
	location / { 
		try_files $uri $uri/ =404;
	} 
	location ~ \.php$ { 
		include snippets/fastcgi-php.conf; 
		fastcgi_pass unix:/var/run/php/php8.3-fpm.sock;
		fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
		include fastcgi_params; 
	} 
}
```


---

3- Enable the nginx server
`
```
sudo systemctl reload nginx
sudo systemctl enable --now nginx
```

---

4- Test the xss vulnerability in the php page we just created

<p align ="center">
    <img src= "/projects/ModSec_Nginx/photo/4-test.png"
</p>

  <p align ="center">
    <img src= "/projects/ModSec_Nginx/photo/5-test_result.png"
</p>
    
---

5- Build ModSecurity

```shell
cd /opt/ModSecurity
sudo git submodule init
sudo git submodule update
sudo ./build.sh
```


---

6- make

```shell
cd /opt/ModSecurity
sudo ./configure
sudo make
sudo make install
```


---

7- Run the configure file in nginx

```shell
cd /opt/nginx-1.28.0
sudo nginx -V
```

and then copy this code from `--with` to the end of the code

<p align ="center">
    <img src= "/projects/ModSec_Nginx/photo/10-ngin-v.png"
</p>

and then write:
```shell
sudo ./configure <the_code> --add-dynamic-module=./ModSecurity-nginx
```

---

8- make modules

```shell
sudo make modules
```


----

9- copy the mosec module to nginx modules

```shell
cd /etc/nginx/
sudo mkdir modules


cd opt/nginx-1.28.0
sudo cpobjs/ngx_http_modsecurity_module.so /etc/nginx/modules
```


----

10- Load the module location to `nginx.conf`

```shell
sudo nano /etc/nginx/nginx.conf
```

`load_module /etc/nginx/module/ngx_http_modsecurity_module.so`

<p align ="center">
    <img src= "/projects/ModSec_Nginx/photo/14-nginx_conf.png"
</p>

---

11- clone the ruleset

```shell
cd /opt
sudo git clone https://github.com/coreruleset/coreruleset /usr/local/modsecurity-crs
```

---

12- rename crs setup file

```shell
cd /opt/modsecurity-crs
sudo mv crs-setup.conf.example crs-setup.conf
```


---

13- move unicode.mapping

```shell
cd /opt
sudo mv /opt/ModSecurity/unicode.mapping /etc/nginx/modsec/
```

---

14- rename modsec.conf

```shell
cd /opt/ModSecurity
sudo mv modsecurity.conf-recommended modsecurity.conf
```

---

15- open the modesecurity conf

add this 

`SecRuleEngine on`

<p align ="center">
    <img src= "/projects/ModSec_Nginx/photo/18-modsec_on.png"
</p>


---

16- create main conf file

```shell
sudo nano /etc/nginx/modsec/main.conf
```

and add:

```
Include /etc/nginx/modsec/modsecurity.conf
Inckude /usr/local/modsecurity-crs/crs-setup.conf
Inckude /usr/local/modsecurity-crs/rules/*.conf
```

<p align ="center">
    <img src= "/projects/ModSec_Nginx/photo/19-create_main.png"
</p>

---

17- open default file of nginx

add:

```
modsecurity on;
modescurity_rules_files /etc/nginx/modsec/main.conf
```

<p align ="center">
    <img src= "/projects/ModSec_Nginx/photo/20-edit_default.png"
</p>

----

18- Restart nginx

```shell
sudo systemctl restart nginx
```

---

19- open the browser and try the xss vuln again, you should face 403 forbidden.


<p align ="center">
    <img src= "/projects/ModSec_Nginx/photo/21-final.png"
</p>

---
## Need More Details?
Feel free to contact me on **[LinkedIn](https://www.linkedin.com/in/saeed-elfiky-61188b24b/)**.  



