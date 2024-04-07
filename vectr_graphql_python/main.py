import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning) # Dissable SSL warnings.
import json

# Define the URL of your GraphQL endpoint
url = 'https://127.0.0.1:8081/sra-purpletools-rest/graphql'  # Replace 'https://example.com/graphql' with your actual GraphQL API endpoint
auth_token = '' # "VEC1 access_key:secret_key" format.

vectr_session = requests.Session()
vectr_session.verify = False
vectr_session.headers.update({
    'Authorization': auth_token
})

class VectrQueries:
    def __init__(self, vectr_session, url) -> None:
        self.vectr_session = vectr_session
        self.url = url

    def grapgql_query(self, query):
        # Make a POST request to the GraphQL endpoint with the query
        response = self.vectr_session.post(url, json={'query': query})

        # Check if the request was successful (status code 200)
        if response.status_code != 200:
            # Print an error message if the request was not successful
            print('Error:', response.status_code)
        
        return response.json(), response.status_code

    def list_databases(self):
        # Define your GraphQL query
        list_databases_query = '''
        query {
        databases {
            name
        }
        }
        '''

        res, status = self.grapgql_query(list_databases_query)
        return res['data']['databases']

    def list_assessments(self, db_name):
        list_assessments_query = '''
        query {{
            assessments(db: "{db_name}"){{
                nodes {{
                    id
                    name
                }}
            }}
        }}
        '''.format(db_name=db_name)

        res, status = self.grapgql_query(list_assessments_query)
        return res['data']['assessments']['nodes']

    def list_campaings(self, db_name, ass_id):
        list_campaings = '''
        query {{
            assessment(db: "{db_name}", id: "{ass_id}"){{
                campaigns {{
                    name,
                    id,
                    offset
                }}
            }}
        }}
        '''.format(db_name=db_name, ass_id=ass_id)

        res, status = self.grapgql_query(list_campaings)
        return res['data']['assessment']['campaigns']

    def list_test_cases(self, db_name, campaign_id):
        list_test_cases = '''
        query {{
            campaign(db: "{db_name}", id: "{campaign_id}") {{
            testCases {{
                name,
                id,
                detectionGuidance
            }}
            }}
        }}
        '''.format(db_name=db_name, campaign_id=campaing_id)

        res, status = self.grapgql_query(list_test_cases)
        return res['data']['campaign']['testCases']

vectr_queries = VectrQueries(vectr_session, url)

databases = vectr_queries.list_databases()
for i,d in enumerate(databases): print(f"{i + 1}. {d['name']}")
db_in = input('Choose database : ')
db_name = databases[int(db_in) - 1]['name']

assesments = vectr_queries.list_assessments(db_name)
for i,d in enumerate(assesments): print(f"{i + 1}. {d['name']}")
ass_in = input('Choose assessment : ')
ass_id = assesments[int(ass_in) - 1]['id']

campaings = vectr_queries.list_campaings(db_name, ass_id)
campaings = sorted(campaings, key=lambda x: x['offset'])
for i,d in enumerate(campaings): print(f"{i + 1}. {d['name']}")
campaing_in = input("Choose campaing: ")
campaing_id = campaings[int(campaing_in) - 1]['id']

test_cases = vectr_queries.list_test_cases(db_name, campaing_id)
print("\nTest cases: ")
test_case_detect_schema = {}
print("\n**** Loading test case detection schemas ****")
for i,d in enumerate(test_cases): 
   name = d['name']
   id  = d['id']
   detection_guidance = d['detectionGuidance']

   print(f"""
Name: {name}
ID: {id}""")
   
   for dg in detection_guidance:
      if "json_schema" in dg:
        payload = dg[len('json_schema:'):].replace("\n", "").replace(" ", "")
        try:
            json_schema = json.loads(payload)
            print("JSON schema loaded for test case: ", id)
        except json.JSONDecodeError as e:
            print("Invalid JSON schema for test case: ", id)
            continue

        if id not in test_case_detect_schema:
            test_case_detect_schema[id] = [json_schema]
        else:
            test_case_detect_schema[id].append(json_schema)

print("\n**** Test case detection schemas ****")
for k,v in test_case_detect_schema.items():
    print(f"\nTest case ID: {k}")
    for d in v: print(f"· {d}")


class VectrMutations:
    def __init__(self, vectr_session, url) -> None:
        self.vectr_session = vectr_session
        self.url = url

    def grapgql_query(self, query):
        # Make a POST request to the GraphQL endpoint with the query
        response = self.vectr_session.post(url, json={'query': query})

        # Check if the request was successful (status code 200)
        if response.status_code != 200:
            # Print an error message if the request was not successful
            print('Error:', response.status_code)
        
        return response.json(), response.status_code
    
    def update_test_case_outcome(self, test_case_id, outcome):
        update_test_case_outcome = '''
        mutation {{
            testCase{{
                update(input: {{db: "FS_THREAT_INDEX", testCaseUpdates: [{{testCaseId: "{test_case_id}", outcome: "{outcome}"}}]}}){{
                    testCases {{
                        id,
                        outcome{{
                            name
                        }}
                    }}
                }}
            }}
        }}
        '''.format(test_case_id=test_case_id, outcome=outcome)

        res, status = self.grapgql_query(update_test_case_outcome)
        print(res)
        return res['data']['testCase']['update']['testCases'][0]
    

vectr_mutations = VectrMutations(vectr_session, url)
res = vectr_mutations.update_test_case_outcome("05ba7e81-fe8c-4e54-876d-6c51c88e1c00", "Blocked")
print(res)