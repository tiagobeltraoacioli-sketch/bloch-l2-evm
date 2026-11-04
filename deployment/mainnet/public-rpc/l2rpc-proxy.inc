# Shared proxy settings for every hop to a settled RPC (included by l2rpc-gateway.conf).
proxy_http_version 1.1;
proxy_method POST;
proxy_pass_request_headers off;
proxy_set_header Connection "";
proxy_set_header Host localhost;
proxy_set_header Content-Type application/json;
proxy_connect_timeout 2s;
proxy_send_timeout 10s;
proxy_buffering on;
proxy_buffer_size 16k;
proxy_buffers 32 64k;
proxy_busy_buffers_size 128k;
proxy_max_temp_file_size 0;
# njs subrequests use the /_l2s/ locations and their own bounded buffer (l2rpc-gateway.conf.in).
proxy_hide_header Access-Control-Allow-Origin;
proxy_hide_header Access-Control-Allow-Methods;
proxy_hide_header Access-Control-Allow-Headers;
proxy_hide_header Vary;
