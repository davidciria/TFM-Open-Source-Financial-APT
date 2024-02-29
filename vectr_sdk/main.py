import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from lxml import html

verbose = False

host = "172.26.128.1:8081"
base_url = "https://{}".format(host)

vectr_session = requests.session()
vectr_session.verify = False
login_url = f"{base_url}/auth/login"

if verbose:
    print("Get JSESSIONID for login")

login_page_res = vectr_session.get(login_url)

if verbose:
    print(vectr_session.cookies)

# Parse the HTML content
tree = html.fromstring(login_page_res.content)
# Use XPath to get the value of the input element
csrf = tree.xpath("/html/body/div/section/form/input/@value")[0]
action = tree.xpath("/html/body/div/section/form/@action")[0]
if verbose:
    print("CSRF:", csrf)
    print("Action:", action)

action_id = action.split('/')[-1]

username = "admin"
password = "11_ThisIsTheFirstPassword_11"

request_login_url = f"{base_url}/auth/login/callback/{action_id}"
try:
    login_request_res = vectr_session.post(
        request_login_url,
        data={
            "_csrf": csrf,
            "username": username,
            "password": password,
        }
    )
except Exception as e:
    raise Exception('Error in login, maybe incorrect username or password')


cookies_dict = {cookie.name: cookie.value for cookie in vectr_session.cookies}
if verbose:
    print(cookies_dict)

if 'vectr_jwt' in cookies_dict:
    print('Logged in succesfully')
else:
    print('Error in login')
    raise Exception('Error in login, maybe incorrect username or password')

def get_envs(vectr_session):
    res = vectr_session.get(f'{base_url}/sra-purpletools-rest/databases')
    return res.json()

def get_assesments(vectr_session, env_name):
    res = vectr_session.post(f'{base_url}/sra-purpletools-rest/assessmentgroups/getInfo?databaseName={env_name}&calculateProgress=false', json={"includes":{"campaignFilterContext":{"testCaseFilterContext":{"redTeamStatuses":["Completed","NotPerformed","InProgress","Paused"],"trueAttackStartTime":{"minDate":None,"maxDate":None},"redTeamToolIds":None,"blueTeamToolIds":None,"targetAssetIds":None,"sourceIpIds":None,"detectionLayerIds":None,"phaseIds":None,"dataScope":{"occurrenceFilter":"NO_FILTER","scoringFilter":"DefenseSuccess"},"blueTeamOutcomeIds":None,"bucketIds":None,"blueTeamOutcomeStates":None,"ids":None,"tagIds":None},"ids":None,"tagIds":None},"ids":None,"tagIds":None},"excludes":{"campaignFilterContext":{"testCaseFilterContext":{"redTeamStatuses":None,"blueTeamOutcomeIds":None,"blueTeamOutcomeStates":None,"ids":None,"tagIds":None},"ids":None,"tagIds":None},"ids":None,"tagIds":None}})
    return res.json()

envs_res = get_envs(vectr_session)
envs = envs_res['data']

for e in envs:
    print("")
    print(f"Environment: {e}")
    assesments_res = get_assesments(vectr_session, e)
    assesment = assesments_res['data']
    for a in assesment:
        assesment_name = a['name']
        print(f"Assesment name: {assesment_name}")