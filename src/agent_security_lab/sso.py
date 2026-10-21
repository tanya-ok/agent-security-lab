# SPDX-FileCopyrightText: 2026 Tanya Babitskaya
# SPDX-License-Identifier: Apache-2.0
"""Bounded issuer-only requests over an existing owned Kubernetes exec channel."""

from urllib.parse import urlsplit

BACKCHANNEL_PATHS = {
    "/.well-known/openid-configuration",
    "/oauth/v2/token",
    "/oauth/v2/keys",
    "/oidc/v1/userinfo",
}
MAX_BODY = 1048576


def allowed_request(method, target, host):
    parsed = urlsplit(target)
    return (
        host == "localhost:4467"
        and not parsed.scheme
        and not parsed.netloc
        and not parsed.fragment
        and parsed.path in BACKCHANNEL_PATHS
        and method in {"GET", "POST"}
        and (method == "GET" or parsed.path == "/oauth/v2/token")
    )


# The child has no Kubernetes credentials and only binds inside the existing pod.
# Its lifetime follows stdin; no daemon, files, volumes or policy changes are created.
POD_RELAY = r"""import base64,json,sys,threading,itertools,time,os
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
lock=threading.Lock();pending={};sequence=itertools.count();slots=threading.BoundedSemaphore(8)
def emit(value):
 with lock:print(json.dumps(value),flush=True)
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):self.exchange()
 def do_POST(self):self.exchange()
 def exchange(self):
  self.connection.settimeout(10)
  if not slots.acquire(blocking=False):self.send_error(503);return
  ident=str(next(sequence));event=threading.Event();item=[event,None]
  try:
   length=int(self.headers.get("Content-Length","0"))
   if not 0<=length<=1048576:self.send_error(413);return
   if self.headers.get("Transfer-Encoding"):self.send_error(400);return
   pending[ident]=item
   emit({"id":ident,"method":self.command,"target":self.path,
         "host":self.headers.get("Host"),"headers":dict(self.headers),
         "body":base64.b64encode(self.rfile.read(length)).decode()})
   if not event.wait(20):self.send_error(503);return
   value=item[1];data=base64.b64decode(value.get("body",""),validate=True)
   self.send_response(value["status"])
   for key,val in value.get("headers",{}).items():self.send_header(key,val)
   self.send_header("Content-Length",str(len(data)));self.send_header("Connection","close")
   self.end_headers();self.wfile.write(data);self.close_connection=True
  except (OSError,ValueError,KeyError):self.close_connection=True
  finally:pending.pop(ident,None);slots.release()
class Server(ThreadingHTTPServer):
 daemon_threads=True
 def handle_error(self,*args):pass
deadline=time.monotonic()+20
while True:
 try:server=Server(("127.0.0.1",4467),Handler);break
 except OSError:
  if time.monotonic()>=deadline:raise
  time.sleep(0.2)
heartbeat=[time.monotonic()]
def watchdog():
 while True:
  time.sleep(0.2)
  if time.monotonic()-heartbeat[0]>12:
   server.shutdown();server.server_close();os._exit(0)
threading.Thread(target=watchdog,daemon=True).start()
thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();emit({"ready":True})
try:
 for line in sys.stdin:
  value=json.loads(line);heartbeat[0]=time.monotonic();item=pending.get(value.get("id"))
  if item:item[1]=value;item[0].set()
finally:server.shutdown();server.server_close()
"""
