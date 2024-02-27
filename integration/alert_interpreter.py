# --------------------------
# Schema
# --------------------------
# Class that helps to interpret an alert to perform a mapping to a test case.

from abc import ABC, abstractmethod
from jsonschema import validate


class AlertInterpreter(ABC):
    def __init__(self) -> None:
        self.use_case_id_schemas = {}

    # Add a schema template associated to a use case.
    @abstractmethod
    def add_schema(self, schema, use_case_id) -> None:
        pass

    # Interpret a payload and try to identify the associated use_case_id. If use_case_id not found return None.
    @abstractmethod
    def interpret(self, payload) -> str:
        pass


class JSONAlertInterpreter(AlertInterpreter):
    def __init__(self) -> None:
        super().__init__()

    def check_payload_schema(self, instance, schema):
        return validate(instance=instance, schema=schema)

    # Schemas should follow the following specification: https://json-schema.org/draft/2020-12/json-schema-validation#name-pattern
    def add_schema(self, schema, use_case_id) -> None:
        if use_case_id in self.use_case_id_schemas:
            self.use_case_id_schemas[use_case_id].append(schema)
        else:
            self.use_case_id_schemas[use_case_id] = [schema]

    def interpret(self, payload) -> str:
        use_case_ids = set()
        for use_case_id in self.use_case_id_schemas:
            for schema in self.use_case_id_schemas[use_case_id]:
                try:
                    self.check_payload_schema(payload, schema)
                    use_case_ids.add(use_case_id)
                except:
                    pass

        return list(use_case_ids)


json_alert_interpreter = JSONAlertInterpreter()
schema = {
    "type": "object",
    "properties": {
        "price": {"type": "number"},
        "name": {"type": "string", "pattern": "helloworld"},
    }
}
json_alert_interpreter.add_schema(schema, "first")
interpreted = json_alert_interpreter.interpret({"name" : "helloworld", "price" : 34.99})
print(interpreted)
