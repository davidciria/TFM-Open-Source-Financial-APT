# --------------------------
# Alert Handler
# --------------------------
# HTTP server that read webhooks alerts send by the SIEM 

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from alert_interpreter import AlertInterpreter

class JSONRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/':
            self.handle_root_post()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

    def handle_root_post(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            json_data = json.loads(post_data.decode('utf-8'))

            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(json_data).encode('utf-8'))

        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'Invalid JSON data')

    def do_GET(self):
        if self.path == '/hello':
            self.handle_hello_get()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

    def handle_hello_get(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Root Page</title>
        </head>
        <body>
            <h1>Welcome to the Root Page!</h1>
        </body>
        </html>
        """
        self.wfile.write(html_content.encode('utf-8'))

def run_server(port=8080):
    server_address = ('', port)
    httpd = HTTPServer(server_address, JSONRequestHandler)
    print(f'Starting server on port {port}...')
    httpd.serve_forever()

if __name__ == '__main__':
    alert_interpreter = AlertInterpreter()
    run_server()
