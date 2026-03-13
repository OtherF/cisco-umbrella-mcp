# Cisco Umbrella API, Samples Overview - Cloud Security API - Cisco DevNet
Cisco Umbrella API, Samples Overview

This guide describes the steps to set up the Cisco Umbrella API client and your local environment to run the sample Python scripts. The samples use the Umbrella API client to generate an OAuth 2.0 access token with your credentials and make requests to the Umbrella API.

*   [Create Your API Key](#!umbrella-api-sample-scripts-overview/create-api-key)
*   [Set Up Environment Variables](#!umbrella-api-sample-scripts-overview/set-up-environment-variables)
*   [Set Up a Virtual Environment](#!umbrella-api-sample-scripts-overview/set-up-virtual-environment)
*   [Install Required Python Libraries](#!umbrella-api-sample-scripts-overview/install-required-python-libraries)
*   [Install the Umbrella API Client Library](#!umbrella-api-sample-scripts-overview/install-umbrella-api-client)
*   [Troubleshooting](#!umbrella-api-sample-scripts-overview/troubleshooting)

Create Your API Key
-------------------

*   Get your Umbrella API key and secret. For more information, see [Umbrella Authentication](#!umbrella-api-authentication).
    *   You will need the API key credentials for your organization to create and manage Umbrella resources.
    *   Your API key must have the permissions to read and write on the API key scopes that includes the resources.
    *   For more information about the API key scopes, see [Umbrella OAuth 2.0 Scopes](#!umbrella-api-oauth-scopes).

Set Up Environment Variables
----------------------------

*   Add your values of the script's environment variables to an `.env` file or set the variables in your environment.
    
*   Set the **OUTPUT\_DIR** environment variable—The directory where the script writes the API response to the files.
    
*   Set the **API\_KEY** environment variable—The API key ID for the organization.
    
*   Set the **API\_SECRET** environment variable—The API key secret for the organization.
    
    ```
  # Add the values for the environment variables

  API_KEY=
  API_SECRET=
  OUTPUT_DIR=

```

    

Set Up a Virtual Environment
----------------------------

Create a Python virtual environment where you will run the sample script.

1.  Set up the virtual environment.
    
    ```
python3 -m venv myenv

```

    
2.  Activate a virtual environment.
    
    ```
myenv\\Scripts\\activate

```

    
    ```
source myenv/bin/activate

```

    

Install Required Python Libraries
---------------------------------

*   A Python 3.x environment with the required libraries installed.
*   You can use the `requirements.txt` file to install the libraries. For more information, see [requirements.txt](#!umbrella-api-sample-scripts-overview/requirements).
*   Run: `pip install -r requirements.txt`

### requirements.txt

```
certifi==2024.8.30
charset-normalizer==3.4.0
idna==3.10
oauthlib==3.2.2
python-dotenv==1.0.1
requests==2.32.3
requests-oauthlib==2.0.0
urllib3==2.2.3
pandas==2.2.3
matplotlib==3.10.1
requests-toolbelt==1.0.0

```


Install the Umbrella API Client Library
---------------------------------------

Set up a directory to locate the Umbrella API Client script. Then follow the steps to install the Umbrella API client library.

1.  Create a directory where you have read and write permissions. The sample scripts may create directories and generate files.
    
    ```
mkdir $HOME/test-scripts

```

    
2.  Set the `CISCO_SAMPLE_DIR` environment variable in your local system to this directory.
    
    ```
export CISCO_SAMPLE_DIR=$HOME/test-scripts

```

    
3.  Navigate to `$CISCO_SAMPLE_DIR` and from that directory create a sub-directory called `cisco`.
    
    ```
cd $CISCO_SAMPLE_DIR
mkdir cisco

```

    
4.  Navigate to `$CISCO_SAMPLE_DIR/cisco` and create an empty `__init__.py` file.
    
    ```
cd $CISCO_SAMPLE_DIR/cisco
touch __init__.py

```

    
5.  Copy and save the [Umbrella API Client](#!umbrella-api-sample-scripts-overview/umbrella-api-client) to `umbrella.py`.
    
6.  Copy `umbrella.py` to `$CISCO_SAMPLE_DIR/cisco`.
    
    ```
cp umbrella.py $CISCO_SAMPLE_DIR/cisco/

```

    

Umbrella API Client
-------------------

```
"""
Copyright (c) 2025 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

import requests
from requests_toolbelt import MultipartEncoder
import os
from dotenv import load_dotenv
from oauthlib.oauth2 import BackendApplicationClient
from oauthlib.oauth2 import TokenExpiredError
from requests_oauthlib import OAuth2Session
from requests.auth import HTTPBasicAuth
from io import StringIO
import pandas as pd
import matplotlib.pyplot as plt

load_dotenv()

# get and set the environment variables
token_url = os.environ.get('TOKEN_URL') or 'https://api.umbrella.com/auth/v2/token'
client_id = os.environ.get('API_KEY') or os.get_env['API_KEY']
client_secret = os.environ.get('API_SECRET') or os.get_env['API_SECRET']

# key scopes
policies = 'policies'
reports = 'reports'
admin = 'admin'
deployments = 'deployments'

PUT = 'put'
POST = 'post'
GET = 'get'
DELETE = 'delete'
PATCH = 'patch'
POST_MULTIPART_FORM_DATA = 'post_multipart_form_data'

# The directory where to write out files
output_dir = os.environ.get('OUTPUT_DIR') or os.get_env['OUTPUT_DIR']

def write_to_csv(df, csv_file):
    if os.path.exists(csv_file):
        df.to_csv(csv_file, mode='a', header=False, index=False)
    else:
        df.to_csv(csv_file, mode='w', header=True, index=False)

class API:
    def __init__(self, url, ident, secret):
        self.url = url
        self.ident = ident
        self.secret = secret
        self.token = None

    def GetToken(self):
        auth = HTTPBasicAuth(self.ident, self.secret)
        client = BackendApplicationClient(client_id=self.ident)
        oauth = OAuth2Session(client=client)
        self.token = oauth.fetch_token(token_url=self.url, auth=auth)
        return self.token

    def Query(self, scope, end_point, operation, request_data=None, files=None, encoder=None):
        success = False
        base_uri = 'https://api.umbrella.com/' + scope + "/v2"
        req = None
        if self.token == None:
            self.GetToken()
        while not success:
            try:
                api_headers = {
                    'Authorization': "Bearer " + self.token['access_token'],
                    "Content-Type": "application/json"
                }

                if operation in GET:
                    req = requests.get('{}/{}'.format(base_uri, end_point), headers=api_headers)
                elif operation in PATCH:
                    req = requests.patch('{}/{}'.format(base_uri, end_point), headers=api_headers, json=request_data)
                elif operation in POST:
                    req = requests.post('{}/{}'.format(base_uri, end_point), headers=api_headers, json=request_data)
                elif operation in POST_MULTIPART_FORM_DATA:
                    # Content-Type is multipart/form-data
                    api_headers_multipart_form_data = {
                        'Authorization': "Bearer " + self.token['access_token'],
                        'Content-Type': encoder.content_type
                    }
                    req = requests.post('{}/{}'.format(base_uri, end_point), data=request_data, headers=api_headers_multipart_form_data)
                elif operation in PUT:
                    req = requests.put('{}/{}'.format(base_uri, end_point), headers=api_headers, json=request_data)
                elif operation in DELETE:
                    req = requests.delete('{}/{}'.format(base_uri, end_point), headers=api_headers, json=request_data)
                req.raise_for_status()
                success = True
            except TokenExpiredError:
                token = self.GetToken()
            except Exception as e:
                raise(e)
        return req

```


Troubleshooting
---------------

1.  Ensure that you installed the libraries that are required to run the script. An example of the error condition when the libraries have not been installed in the Python environment:
    
    `ModuleNotFoundError: No module named 'requests'`
    
2.  Ensure that you set up the environment variables in the `.env` file for the script. You can also set the environment variables in the shell where you run the script. An example of the error condition when the environment variables are not set:
    
    `(missing_token) Missing access token parameter.`
    
3.  When you copy and save a sample script in your local environment, check that the sample does not contain an HTML entity, for example: (`&gt;`). Replace the HTML greater than (`&gt;`) sign with the greater than (`>`) symbol.