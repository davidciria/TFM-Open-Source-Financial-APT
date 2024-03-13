# --------------------------
# Alert Handler
# --------------------------
# HTTP server that read webhooks alerts send by the SIEM

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from alert_interpreter import JSONAlertInterpreter
from datetime import datetime
import logging

server_port = 8080

logging.basicConfig(
    filename="requests.log", level=logging.INFO, format="%(asctime)s - %(message)s"
)
json_alert_interpreter = JSONAlertInterpreter()


class JSONRequestHandler(BaseHTTPRequestHandler):

    
    def do_GET(self):
        if self.path == "/":
            self.handle_hello_get()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self):
        if self.path == "/interpret":
            self.handle_interpret()
        elif self.path == "/add_schema":
            self.handle_add_schema()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def handle_add_schema(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)

        try:
            json_data = json.loads(post_data.decode("utf-8"))

            schema = json_data.get("schema")
            use_case_id = json_data.get("use_case_id")

            if schema and use_case_id:
                if json_alert_interpreter.add_schema(schema, use_case_id):
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(
                        json.dumps(
                            {"status": "200", "message": "Schema added succesfully"}
                        ).encode("utf-8")
                    )
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(
                        b"Invalid JSON schema (schema does not follow Draft7 syntax)"
                    )
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(
                    b"Invalid JSON data (does not contain schema or use_case_id)"
                )
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid JSON data")

    def handle_interpret(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)

        try:
            json_data = json.loads(post_data.decode("utf-8"))

            print(f"Alert recieved: {json_data}")
            use_cases = json_alert_interpreter.interpret(json_data)

            # Log timestamp, alert_received, and types detected
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_event = {"alert_recieved": json_data, "use_cases": use_cases}
            log_message = (
                f"{timestamp} - {json.dumps(log_event, separators=(',', ':'))}"
            )
            logging.info(log_message)

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(log_event).encode("utf-8"))

        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid JSON data")

    def handle_hello_get(self):

        script = """
            <script>
                let add_schema_req = {
                    "use_case_id": "example_id",
                    "schema": {
                        "type": "object",
                        "required": [
                            "attack_type"
                        ],
                        "properties": {
                            "attack_type": {
                                "type": "string",
                                "enum": [
                                    "phishing"
                                ]
                            }
                        },
                        "additionalProperties": false
                    }
                }
                document.getElementById("add_schema_req").textContent = JSON.stringify(add_schema_req, undefined, 2);
            </script>
        """

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Alert Handler</title>
        </head>
        <body>
            <h1>Welcome to alert handler!</h1>
            <p>HTTP server that read webhooks alerts send by the SIEM</p>
            <h2>Routes</h2>

            <h3>Add schema</h3>
            <div><strong>POST</strong> http://localhost:{server_port}/add_schema</div>
            <h4>Example request</h4>
            <div style="background: black; color: white; padding: 5px; display: inline-block;">
            <pre style="margin:0" id="add_schema_req">
            </pre>
            </div>
            <h4>Example response</h4>

            <h3>Interpret Alert</h3>
            <div><strong>POST</strong> http://localhost:{server_port}/interpret</div>
            <h4>Example request</h4>
            <h4>Example response</h4>

            {script}
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(html_content.encode("utf-8"))


def run_server(port=server_port):
    server_address = ("", port)
    httpd = HTTPServer(server_address, JSONRequestHandler)
    print(f"Starting server on port {port}...")
    httpd.serve_forever()


if __name__ == "__main__":

    schema = {
        "type": "object",
        "required": ["attack_type"],
        "properties": {"attack_type": {"type": "string", "enum": ["phishing"]}},
        "additionalProperties": False,
    }
    json_alert_interpreter.add_schema(schema, "phising_attack")
    run_server()
