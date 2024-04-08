# --------------------------
# Schema
# --------------------------
# Class that helps to interpret an alert to perform a mapping to a test case.

from abc import ABC, abstractmethod
from jsonschema import validate, Draft7Validator, exceptions


class AlertInterpreter(ABC):
    def __init__(self) -> None:
        self.use_case_id_schemas = {}

    # Add a schema template associated to a use case.
    @abstractmethod
    def add_schema(self, schema, use_case_id) -> None:
        pass

    # Remove a schema template associated to a use case.
    @abstractmethod
    def remove_schema(self, schema, use_case_id) -> None:
        pass

    # Remove a schema template associated to a use case.
    @abstractmethod
    def remove_all_schemas(self) -> None:
        pass

    # Interpret a payload and try to identify the associated use_case_id. If use_case_id not found return None.
    @abstractmethod
    def interpret(self, payload) -> str:
        pass


class JSONAlertInterpreter(AlertInterpreter):
    def __init__(self) -> None:
        super().__init__()

    def check_payload_schema(self, _instance, _schema):
        return validate(instance=_instance, schema=_schema)

    # Schemas should follow the following specification: https://json-schema.org/draft/2020-12/json-schema-validation#name-pattern
    def add_schema(self, schema, use_case_id) -> None:

        try:
            # Validate the schema against the JSON Schema Draft specification
            Draft7Validator.check_schema(schema)
            print("Schema is valid.")
        except exceptions.SchemaError as e:
            print(f"Schema validation failed: {e}")
            return False

        if use_case_id in self.use_case_id_schemas:
            self.use_case_id_schemas[use_case_id].append(schema)
        else:
            self.use_case_id_schemas[use_case_id] = [schema]
        
        return True
    
    def remove_schema(self, schema, use_case_id) -> None:
        if use_case_id in self.use_case_id_schemas:
            self.use_case_id_schemas[use_case_id].remove(schema)
        else:
            print(f"Use case id {use_case_id} not found.")
        
        return True
    
    def remove_all_schemas(self) -> None:
        self.use_case_id_schemas = {}
        return True

    def interpret(self, payload) -> str:
        use_case_ids = set()
        for use_case_id in self.use_case_id_schemas:
            for schema in self.use_case_id_schemas[use_case_id]:
                try:
                    print(payload, schema)
                    self.check_payload_schema(payload, schema)
                    use_case_ids.add(use_case_id)
                except:
                    pass

        return list(set(use_case_ids))