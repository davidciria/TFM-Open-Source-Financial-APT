# --------------------------
# Alert Handler
# --------------------------
# HTTP server that read webhooks alerts send by the SIEM

from flask import Flask, request, jsonify, render_template
from datetime import datetime
from alert_interpreter import JSONAlertInterpreter
import logging

app = Flask(__name__)

# logging.basicConfig(
#     filename="requests.log", level=logging.INFO, format="%(asctime)s - %(message)s"
# )
json_alert_interpreter = JSONAlertInterpreter()


@app.route("/", methods=["GET"])
def handle_hello_get():
    html_params = {"request_host": request.host}

    return render_template("doc.html", **html_params)


@app.route("/add_schema", methods=["POST"])
def handle_add_schema():
    try:
        json_data = request.get_json()
        schema = json_data.get("schema")
        use_case_id = json_data.get("use_case_id")

        if schema and use_case_id:
            if json_alert_interpreter.add_schema(schema, use_case_id):
                return (
                    jsonify({"status": "200", "message": "Schema added succesfully"}),
                    200,
                )
            else:
                return "Invalid JSON schema (schema does not follow Draft7 syntax)", 400
        else:
            return "Invalid JSON data (does not contain schema or use_case_id)", 400
    except Exception as e:
        return "Invalid JSON data", 400


@app.route("/interpret", methods=["POST"])
def handle_interpret():
    try:
        json_data = request.get_json()
        print(f"Alert received: {json_data}")
        use_cases = json_alert_interpreter.interpret(json_data)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_event = {"alert_received": json_data, "use_cases": use_cases}
        log_message = f"{timestamp} - {log_event}"
        logging.info(log_message)

        return jsonify(log_event), 200
    except Exception as e:
        return "Invalid JSON data", 400


if __name__ == "__main__":
    schema = {
        "type": "object",
        "required": ["attack_type"],
        "properties": {"attack_type": {"type": "string", "enum": ["phishing"]}},
        "additionalProperties": False,
    }
    json_alert_interpreter.add_schema(schema, "phishing_attack")
    app.run(port=8080)
