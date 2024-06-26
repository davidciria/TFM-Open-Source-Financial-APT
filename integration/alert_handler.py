# --------------------------
# Alert Handler
# --------------------------
# HTTP server that read webhooks alerts send by the SIEM

from flask import Flask, request, jsonify, render_template
import threading
from datetime import datetime
from alert_interpreter import JSONAlertInterpreter
import logging
from vectr_graphql import load_detection_schemas, mark_test_case_as_alert_detected
import time

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
        for uc in use_cases:
            mark_test_case_as_alert_detected(uc, test_case_detect_schemas, db_name)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_event = {"alert_received": json_data, "use_cases": use_cases}
        log_message = f"{timestamp} - {log_event}"
        logging.info(log_message)

        return jsonify(log_event), 200
    except Exception as e:
        return "Invalid JSON data", 400

def menu():
    while True:
        time.sleep(2)
        print("Menu:")
        print("1. Change campaign")
        print("2. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            json_alert_interpreter.remove_all_schemas()
            test_case_detect_schemas, db_name = load_detection_schemas()
            for k,v in test_case_detect_schemas.items():
                for d in v:
                    json_alert_interpreter.add_schema(d, k)
        elif choice == '2':
            print("Press control + c to exit the application.")
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    test_case_detect_schemas, db_name = load_detection_schemas()
    for k,v in test_case_detect_schemas.items():
        for d in v:
            json_alert_interpreter.add_schema(d, k)

    # Create a thread for the menu
    menu_thread = threading.Thread(target=menu)
    menu_thread.start()

    app.run(port=8080)
