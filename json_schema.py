from jsonschema import validate

schema = {
    "type": "object",
    "additionalProperties": {
        "type": "object",
        "properties": {"element": {"type": "string", "enum": ["one"]}},
        "required": ["element"],
        "additionalProperties": False,
    },
}

# Examples to validate against the schema
data1 = {"papi": {"element": "one", "aditional": "sda"}}

data2 = {"mami": {"element": "one"}}

try:
    validate(instance=data1, schema=schema)
    print("Data1 is valid.")
except Exception as e:
    print(f"Data1 is not valid: {e}")

try:
    validate(instance=data2, schema=schema)
    print("Data2 is valid.")
except Exception as e:
    print(f"Data2 is not valid: {e}")
