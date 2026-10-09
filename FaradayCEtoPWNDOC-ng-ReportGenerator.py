import csv
import requests
import json
import html
# Credentials are not exposed in the call/process file, but stored in a seperate credentials file
from credentials import FARADAYUSER
from credentials import FARADAYPASS
from credentials import PWNDOC_URL
from credentials import PWNDOCUSER
from credentials import PWNDOCPASS
from credentials import AUDIT_NAME
from credentials import faradaycsv
from credentials import FARADAY_URL

## Evaluate the credentials and file configuration, take input for non suppled credentials. # TODO will add values for PWNDOC when necessary
if FARADAYUSER == '':
	FARADAYUSER = (input("FARADAY user: "))

if FARADAYPASS == ' ':
	FARADAYPASS = (input("FARADAY password: "))

if faradaycsv == '':
	faradaycsv = (input("Faraday CSV output file with ID in LAST position: "))

if PWNDOCUSER == '':
        PWNDOCUSER = (input("PWNDOC-NG username: "))

if PWNDOCPASS == '':
	PWNDOCPASS = (input("PWNDOC-NG user password: "))



## Standard export format is SR-PROJECT.csv. Parse the filename to determine 'project' for later use in api url call.

project = (((faradaycsv.split('.'))[0]).split('-'))[1]
print (project)


## Function to define request for json format output of vuln by id from faraday api

def vulnrequest(id):
	vulnurl = FARADAY_URL+'/_api/v3/ws/'+project+'/vulns/'+id+''
	faradayresponse = faradaysession.get(vulnurl)
	print ("Get Vuln "+id+": ",faradayresponse.status_code)
	if faradayresponse.status_code != 200:
		raise SystemExit("Could not retrieve vuln")
	vuln = faradayresponse.json()
	return vuln

## Function to parse vuln data from faraday api. Comments notes are development notes for the intended transforms to pwndoc-ng

def parse_vuln(vuln):
	parsed = {}
	parsed['id'] = vuln.get('id')
	parsed['confirmed'] = vuln.get('confirmed') # necessary to report validity. Will only wish to report True items
	parsed['type'] = vuln.get('type')
	parsed['name'] = vuln.get('name') # maps to pwndoc Title
	parsed['description'] = vuln.get('description') # Maps to pwndoc definition>description
	parsed['resolution'] = vuln.get('resolution') # maps to pwndoc details>remediation
	parsed['target'] = vuln.get('target') # maps to pwndoc details>affected assets, possibly also to definition>observation
	parsed['hostnames'] = vuln.get('hostnames') # maps to pwndoc details> observation
	parsed['cve'] = vuln.get('cve') # maps to pwndoc details>references
	parsed['cwe'] = vuln.get('cwe') # maps to pwndoc details>references
	parsed['data'] = vuln.get('data') #TODO define where this goes - the 'last observed' should be mapped to pwndoc>definitions> observations
	parsed['last_detected'] = vuln.get('last_detected')
	parsed['date'] = vuln.get('date')
	parsed['update_date'] = vuln.get('update_date')
	parsed['service'] = vuln.get('service') # TODO define usage, likely maps to pwndoc>definitions>observation
	parsed['severity'] = vuln.get('severity') # maps to pwndoc priority, change value from text to number for pwndoc import: info: 0, low: 1, med: 2, medium: 2, high: 3, critical: 4
	parsed['tool'] = vuln.get('tool') # should be recorded somewhere, perhaps in pwndoc 'observation' section
	parsed['external_id'] = vuln.get('external_id') #details version of tool used, should probably be recorded somewhere
	parsed['easeofresolution'] = vuln.get('easeofresolution') #maps to pwndock 'remediation difficulty'. Not yet sure of how data translates.
	parsed['host_os'] = vuln.get('host_os') # maps to pwndoc details > observation
	parsed['refs'] = vuln.get('refs') # maps to pwndoc refererences

## web section - not sure how we'll designate all of these fields yet. Not all may be necessary for report. Not all may be populated depending on dataset.
	parsed['method'] = vuln.get('method')
	parsed['path'] = vuln.get('path')
	# Request and response bodies will map to proofs in pwndoc formatted as codeblocks
	parsed['request'] = vuln.get('request')
	parsed['response'] = vuln.get('response')
	parsed['status_code'] = vuln.get('status_code') # we may be able to additionally use this to determine DOS/service failure, but not prioritizing logic usage for this yet
	parsed['website'] = vuln.get('website')
	parsed['owasp'] = vuln.get('owasp')
	parsed['params'] = vuln.get('params')
	parsed['pname'] = vuln.get('pname')
	parsed['query'] = vuln.get('query')
	parsed['impact'] = vuln.get('impact')

### CVSS parse: attempt to preserve as much CVSS translation from sources into faraday as possible

	parsed['cvss'] = {}

	cvss2 = vuln.get('cvss2') or {}
	vector = cvss2.get('vector_string')

	if vector:
		parsed['cvss']['version'] = 2
		parsed['cvss']['vector'] = vector
		parsed['cvss']['score'] = cvss2.get('base_score')
		parsed['cvss']['severity'] = cvss2.get('base_severity')
		cvssv3 = []

		for metric in vector.split('/'):
			key, value = metric.split(':')
			if key == 'AV':
				cvssv3.append('AV:'+value)
			elif key == 'AC':
				if value == 'L':
					cvssv3.append('AC:L')

			elif key == 'Au':
				if value == 'N':
					cvssv3.append('PR:N')

			elif key == 'C':
				if value == 'N':
					cvssv3.append('C:N')
				elif value == 'P':
					cvssv3.append('C:L')
				elif value == 'C':
					cvssv3.append('C:H')

			elif key == 'I':
				if value == 'N':
					cvssv3.append('I:N')
				elif value == 'P':
					cvssv3.append('I:L')
				elif value == 'C':
					cvssv3.append('I:H')

			elif key == 'A':
				if value == 'N':
					cvssv3.append('A:N')
				elif value == 'P':
					cvssv3.append('A:L')
				elif value == 'C':
					cvssv3.append('A:H')

		parsed['cvss']['cvssv3'] = '/'.join(cvssv3)

	else:
		impact = vuln.get('impact') or {}

		parsed['cvss']['version'] = None
		parsed['cvss']['vector'] = None
		parsed['cvss']['score'] = None
		parsed['cvss']['severity'] = None

		impact_cvss = []
# In the event of no CVSS score from vuln scanner, user may assign IMPACT toggles in faraday. These will default to LOW CVSS scores for C/I/A. User is responsible for update in pwndoc
		if impact.get('confidentiality'):
			impact_cvss.append('C:L')

		if impact.get('integrity'):
			impact_cvss.append('I:L')

		if impact.get('availability'):
			impact_cvss.append('A:L')

		parsed['cvss']['cvssv3'] = '/'.join(impact_cvss)

	return parsed



### function to process html formatting into json for pwndoc field insert

def html_paragraph(text):
	if not text:
		return ''

	text = html.escape(str(text))
	paragraphs = text.split('\n\n')

	return ''.join(
		'<p>' + paragraph.replace('\n', '<br>') + '</p>'
		for paragraph in paragraphs
		if paragraph.strip()
	)

### function to parse faraday json to pwndoc json. Transforms values of faraday to PWNDOC-NG report

def pwndocfinding(parsed):
	finding = {}
	finding['confirmed'] = parsed.get('confirmed')
	finding['title'] = parsed.get('name') or ''
	finding['type'] = parsed.get('type') or ''
	finding['description'] = html_paragraph(parsed.get('description')) or ''
	finding['remediation'] = html_paragraph(parsed.get('resolution')) or ''
	finding['priority'] = parsed.get('severity') or 'info'
### Convert easeofresolution to remediationComplexity. Approximate transform.
	if parsed.get('easeofresolution') == "trivial":
		finding['remediationComplexity'] = '1'
	if parsed.get('easeofresolution') == "simple":
		finding['remediationComplexity'] = '1'
	if parsed.get('easeofresolution') == "moderate":
		finding['remediationComplexity'] = '2'
	if parsed.get('easeofresolution') == "difficult":
		finding['remediationComplexity'] = '3'
# Uncomment if you want to define "infeasable" as 'complex'
#	if parsed.get('easeofresolution') == "infeasible":
#		finding['remediationComplexity'] = '3'
	finding['os'] = parsed.get("host_os") or ''
	finding['scope'] = parsed.get('target')
## Convert priority:
	if finding['priority'] == "critical":
		finding['priority'] = '4'
	elif finding['priority'] == "high":
		finding['priority'] = '3'
	elif finding['priority'] == "medium":
		finding['priority'] = '2'
	elif finding['priority'] == "med":
		finding['priority'] = '2'
	elif finding['priority'] == "low":
		finding['priority'] = '1'
	else:
		finding['priority'] = '0'

# Build a basic observation from the Faraday target information.
	observation = []

	if parsed.get('target'):
		observation.append("Target: "+str(parsed['target']))

	if parsed.get('hostnames'):
		observation.append("Hostname(s): "+", ".join(parsed['hostnames']))
	if finding['os'] != '':	
		observation.append("Operating System: "+str(finding['os']))
	if parsed.get('tool'):
		observation.append("Tool: "+str(parsed['tool']))

	if parsed.get('external_id'):
		observation.append("External ID: "+str(parsed['external_id']))

## Add observation values if web vulnerability.
# (I tend to do do mostly web oriented observations, so this may be less critical for you)
	if parsed.get('type') == "VulnerabilityWeb":
		observation.append('''Web Vulnerability Findings:
		''')
		if parsed.get('website'):
			observation.append('''Website: 
			'''+str(parsed['website']))
		if parsed.get('path'):
			observation.append('''Path:
			'''+str(parsed['path']))
		if parsed.get('params'):
			observation.append('''Parameters:
			'''+str(parsed['params']))
		if parsed.get('pname'):
			observation.append('''Parameter name:
			'''+str(parsed['pname']))
		if parsed.get('query'):
			observation.append('''Query: '''
			+str(parsed['query']))
		if parsed.get('method'):
			observation.append('''Method:
			'''+str(parsed['method']))
	finding['observation'] = '<p>'+'<br>'.join(observation)+'</p>' if observation else ''

# Build References list
	references = []
	if parsed.get('cve'):
		for cve in parsed['cve']:
			references.append("CVE: "+str(cve))

	if parsed.get('cwe'):
		for cwe in parsed['cwe']:
			references.append("CWE: "+str(cwe))

	if parsed.get('refs'):
		for ref in parsed['refs']:
			if isinstance(ref, dict):
				refname = ref.get('name')
				if refname:
					references.append(str(refname))
			else:
				references.append(str(ref))

	finding['references'] = references if references else ''

# Build proof - IMPORTANT NOTE: the faraday json api CAN NOT translate IMAGE FILE EVIDENCE. You'll have to manually import it. This is mostly tuned for web http request/response
	pocparts = []
	if parsed.get('type') == "VulnerabilityWeb":
		if parsed.get('request'):
			pocparts.append(
				'<p><strong>HTTP Request<strong></p>'
				'<pre><code class="language-http">'
				+ html.escape(str(parsed.get('request')))
				+ '</code></pre>'
			)
		if parsed.get('response'):
			pocparts.append(
				'<p><strong>HTTP Response<strong></p>'
				'<pre><code class="language-http">'
				+ html.escape(str(parsed.get('response')))
				+ '</code></pre>'
			)
	finding['poc'] = ''.join(pocparts) if pocparts else ''


# Build CVSS
	cvss = parsed.get('cvss') or {}

	if parsed['cvss'].get('cvssv3'):
		finding['cvssv3'] = 'CVSS:3.1/' + parsed['cvss']['cvssv3']

	return finding







##########################
#### START


faradaysession = requests.Session()
faradaysession.verify = False


## Login to faraday, get cookie session token.
faradayresponse = faradaysession.post(
	f"{FARADAY_URL}/_api/login",
	json={
		"email": FARADAYUSER,
		"password": FARADAYPASS,
		"remember": "false"
	}
)
print ("Login: ", faradayresponse.status_code)
print(faradayresponse.text)

if faradayresponse.status_code != 200:
	raise SystemExit("Login Failed")


pwndocsession = requests.Session()
pwndocsession.verify = False

# Login to Pwndoc, get cookie session
pwndocresponse = pwndocsession.post(
	 f"{PWNDOC_URL}/api/users/token",
	 json={
		 "username": PWNDOCUSER,
		 "password": PWNDOCPASS
	}
)

print("Login:", pwndocresponse.status_code)
print(pwndocresponse.text)

if pwndocresponse.status_code != 200:
	raise SystemExit("Login failed")

# Get audits from pwndoc
pwndocresponse = pwndocsession.get(f"{PWNDOC_URL}/api/audits")

print("Get audits:", pwndocresponse.status_code)

if pwndocresponse.status_code != 200:
	raise SystemExit("Could not retrieve audits")

audits = pwndocresponse.json()
print (audits)

# Find intended audit
audit_id = None

for audit in audits["datas"]:
	if audit["name"] == AUDIT_NAME:
		audit_id = audit["_id"]
		break

if audit_id is None:
	raise SystemExit(f"Audit '{AUDIT_NAME}' not found")

print("Audit ID:", audit_id)


## Pen CSV file
with open(faradaycsv, newline='', encoding='utf-8') as openfile:
	next(openfile)
##
	reader=csv.reader(openfile)
	for row in reader:
## Formatting REQUIREMENT: 'id' field must be selected in the faraday csv output and placed in the LAST position in the row
		id = (str(row[-1]))
		vulnjson = vulnrequest(id)
		parsed = parse_vuln(vulnjson)
###!		VVV  selects ONLY 'confirmed' findings in FARADAY to be parsed into pwndoc-ng.
		confirmstatus = (parsed['confirmed'])
#! 		Uncomment VV THIS line if you just want everything
#		confirmstatus = True
		if confirmstatus == True:
			finding = pwndocfinding(parsed)
			print (finding) 
		# Insert finding
			pwndocresponse = pwndocsession.post(
				f"{PWNDOC_URL}/api/audits/{audit_id}/findings",
			json=finding
			)
