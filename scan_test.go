package main

import (
	"reflect"
	"testing"
)

// nginx -T 把 include 的文件附在主配置之后输出，站点通常写在这些文件里
func TestParseNginxDumpFollowsIncludes(t *testing.T) {
	dump := []byte(`# configuration file /etc/nginx/nginx.conf:
http {
    include mime.types;
    include /etc/nginx/conf.d/*.conf;
}

# configuration file /etc/nginx/mime.types:
types {
    text/html html;
}

# configuration file /etc/nginx/conf.d/a.conf:
server {
    listen 443 ssl;
    server_name a.example.com;
    include snippets/ssl.conf;
}

# configuration file /etc/nginx/snippets/ssl.conf:
ssl_certificate /etc/ssl/a/fullchain.pem;
ssl_certificate_key /etc/ssl/a/privkey.pem;

# configuration file /etc/nginx/conf.d/b.conf:
server {
    listen 443 ssl;
    server_name b.example.com;
    ssl_certificate /etc/ssl/b/fullchain.pem;
    ssl_certificate_key /etc/ssl/b/privkey.pem;
}
`)
	want := []certPair{
		{serverNames: []string{"a.example.com"}, certPath: "/etc/ssl/a/fullchain.pem", keyPath: "/etc/ssl/a/privkey.pem", listens: []string{"127.0.0.1:443"}},
		{serverNames: []string{"b.example.com"}, certPath: "/etc/ssl/b/fullchain.pem", keyPath: "/etc/ssl/b/privkey.pem", listens: []string{"127.0.0.1:443"}},
	}
	if got := parseNginxDump(dump); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
