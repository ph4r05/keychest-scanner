# Remote certbot domain validation

In order to perform domain validation for managed domains on the agent server the virtual host of the validated domain
has to be configured in a way it proxies `.well-known` directory to the local KeyChest agent running Certbot.

## Nginx

```
location /.well-known {
    resolver         8.8.8.8;
    proxy_pass       https://agent.keychest.net/_le/${host}${uri};
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

- May work only over http - debug.

## Apache

```
SSLProxyEngine On
SSLProxyCheckPeerCN on
SSLProxyCheckPeerExpire on

RewriteEngine on
RewriteCond %{HTTP_HOST} (.*)
RewriteRule "^/.well-known/(.*)$" "https://dev.keychest.net/_le/%{HTTP_HOST}/.well-known/$1" [P,L,QSA]
ProxyPassReverse ".well-known/"  "http://dev.keychest.net"
```

