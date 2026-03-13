# Cisco Umbrella API, Getting Started - Cloud Security API - Cisco DevNet
Cisco Umbrella API, Getting Started

The Cisco Umbrella API provides a RESTful interface that is described by version 3.x of the OpenAPI specification. Umbrella API endpoints use JSON for all requests and responses.

Umbrella API Resources
----------------------

### Admin Resources

*   **Key Admin API**—Create and manage Umbrella API keys.
*   **Users and Roles API**—Get the organization's user accounts and user roles.
*   **S3 Bucket Key Rotation API**—Refresh the Cisco-managed S3 bucket key for the organization.
*   **Providers Console Configuration API**–Create, get, and manage the Cname, Contact, and Logo information for a service provider console.
*   **Providers API**–Create, view, update, and delete Managed Services Console data for the customers in your organizations.
*   **Managed Providers API**–Create, get, and manage Multi-Org or Managed Services Providers (MSP) console data for customers in your organizations.

### Deployments Resources

*   **Networks API**—Create, get, and manage the Networks and Network deployment policies in the organization.
*   **Internal Domains API**—Create, get, and manage the Internal Domains in the organization.
*   **Internal Networks API**—Create, get, and manage the Internal Networks and internal network deployment policies in the organization.
*   **Roaming Computers API**—Get and manage the Roaming Computers in the organization.
*   **Sites API**—Create, get, and manage the Sites in the organization.
*   **Virtual Appliances API**—Get and manage the Virtual Appliances in the organization.
*   **Network Tunnels API**—Create, get, and manage the Network Tunnels in the organization. View the datacenters for the Network Tunnels.
*   **Network Devices API**—Create, get, and manage the Network Devices in the organization.
*   **Policies API**—Get and manage the Policies about the organization's deployments.
*   **Tagging API**—Get and manage the tags for the Roaming Computers in the organization.
*   **Secure Web Gateway Device Settings API**—Get and manage the Secure Web Gateway (SWG) override settings for devices, which are registered with Umbrella.

### Investigate Resources

*   **Umbrella Investigate API**—Get the information about domains, IPs, and URLs observed by the Umbrella DNS resolvers.

### Policies Resources

*   **Destination Lists API**—Create, get, and manage Destination Lists and destinations.
*   **Application Lists API**—Create, view, and manage Application Lists and internet applications.

### Reports Resources

*   **Reporting API**—Get the Umbrella reports (activity, top threats, top destinations, top identities, top IPs, summary, threat types).
*   **App Discovery API**—Get reports about traffic in your organization to cloud applications, application protocols, and application categories.
*   **API Usage Reports API**—Get the reports for the organization's API usage.
*   **Providers Consoles API**–Get the reports for the provider and managed provider consoles.

Base URI
--------

The Umbrella API endpoints begin with the `api.umbrella.com` base URI.

The API endpoints use the following API path scopes:

*   `https://api.umbrella.com/admin/v2`
*   `https://api.umbrella.com/auth/v2`
*   `https://api.umbrella.com/deployments/v2`
*   `https://api.umbrella.com/investigate/v2`
*   `https://api.umbrella.com/policies/v2`
*   `https://api.umbrella.com/reports/v2`

The Umbrella Token Authorization API reads your API credentials and returns a Bearer token. Include your short-lived token in the `Authorization` header of each Umbrella API operation.

For information about creating your Umbrella API credentials, see [Authentication](#!umbrella-api-authentication).

### Best Practices

The Umbrella Token Authorization API endpoint supports the [OAuth 2.0 Client Credentials Flow](https://tools.ietf.org/html/rfc6749#section-4.4). Umbrella only accepts API credentials (key and secret) created by a valid Umbrella account. Umbrella can’t authenticate requests for deactivated accounts.

> **Note:** An Umbrella OAuth 2.0 access token expires in one hour (3600 seconds). We recommend that you do not refresh an access token until the token is nearly expired.

### Generate an API Access Token

The Umbrella Token Authorization API endpoint:

POST `https://api.umbrella.com/auth/v2/token`

> **Note:** You can use any standards-based OAuth 2.0 client library to create an API access token.

### Request

Run the `curl` or Python sample, providing your Umbrella API key and secret.

```
curl --user '<key>:<secret>' --request POST --url 'https://api.umbrella.com/auth/v2/token' \
-H 'Content-Type: application/x-www-form-urlencoded' \
-d 'grant_type=client_credentials'

```


```
import requests
import json
import os
import time
from oauthlib.oauth2 import BackendApplicationClient
from oauthlib.oauth2 import TokenExpiredError
from requests_oauthlib import OAuth2Session
from requests.auth import HTTPBasicAuth

token_url = os.environ.get('TOKEN_URL') or 'https://api.umbrella.com/auth/v2/token'

# Export/Set the environment variables
client_id = os.environ.get('API_KEY')
client_secret = os.environ.get('API_SECRET')

class UmbrellaAPI:
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

# Exit out if the client_id, client_secret are not set
for var in ['API_SECRET', 'API_KEY']:
    if os.environ.get(var) == None:
        print("Required environment variable: {} not set".format(var))
        exit()

# Get token
api = UmbrellaAPI(token_url, client_id, client_secret)
print("Token: " + str(api.GetToken()))

```


### Response Schema


|Name        |Type   |Description                                    |
|------------|-------|-----------------------------------------------|
|token_type  |string |The type of access token.                      |
|access_token|string |The OAuth 2.0 access token.                    |
|expires_in  |integer|The number of seconds before the token expires.|


### Response

Sample response (`200`, OK):

```
{
   "token_type": "bearer",
   "access_token": "xxxxxx",
   "expires_in": 3600
}

```


Sample API Request
------------------

To make an Umbrella API request, substitute your Bearer token in the HTTP `Authorization` header.

For example:

```
curl -L --location-trusted --request GET --url 'https://api.umbrella.com/admin/v2/users' \
-H 'Authorization: Bearer %YourAcessToken%' \
-H 'Content-Type: application/json'

```


### Expired Access Token

If you provide an expired API access token in the `Authorization` header of an API operation, Umbrella responds with an HTTP `400` (Bad Request) error.

For example:

```
{ "error": "invalid_request" }

```


To resolve the error condition, generate a new access token through the Umbrella Token Authorization API.

Token Authorization Request for Multi-Org and Managed Child Organizations
-------------------------------------------------------------------------

Create your Umbrella API credentials (parent org) on the Multi-org or provider console. Then, use these credentials to generate an API access token for the parent (provider) organization or the child (customer) organization of the provider.

### API Endpoints Available For Parent and Child Organizations

These API endpoints only accept a parent (provider) organization access token. You can specify the child organization ID in the `X-Umbrella-OrgId` request header to generate the access token for a specific child (customer) organization of the provider.

*   GET `/admin/v2/config/contacts`
*   POST `/admin/v2/config/contacts`
*   GET `/admin/v2/config/contacts/{contactId}`
*   PUT `/admin/v2/config/contacts/{contactId}`
*   DELETE `/admin/v2/config/contacts/{contactId}`
*   GET `/admin/v2/config/logos`
*   POST `/admin/v2/config/logos`
*   GET `/admin/v2/config/logos/{logoId}`
*   PUT `/admin/v2/config/logos/{logoId}`
*   DELETE `/admin/v2/config/logos/{logoId}`

### API Endpoints Available Only For Parent Organizations

The following API endpoints only accept an access token generated with a parent (provider) organization's API credentials. Set a child organization ID for the `customerId` path parameter.

*   GET `/admin/v2/config/cnames`
*   POST `/admin/v2/config/cnames`
*   GET `/admin/v2/config/cnames/{cnameId}`
*   PUT `/admin/v2/config/cnames/{cnameId}`
*   DELETE `/admin/v2/config/cnames/{cnameId}`
*   POST `/admin/v2/providers/customers/{customerId}/trialExtensions`
*   POST `/admin/v2/providers/customers/{customerId}/accessRequests`
*   GET `/admin/v2/providers/customers/{customerId}/accessRequests/{accessRequestId}`
*   PUT `/admin/v2/providers/customers/{customerId}/accessRequests/{accessRequestId}`
*   GET `/admin/v2/providers/customers/{customerId}/trialStrengths`
*   GET `/admin/v2/providers/customers/{customerId}/subscriptionDetails`
*   GET `/admin/v2/providers/customerAddresses`
*   GET `/admin/v2/providers/customers/packages`
*   GET `/admin/v2/providers/customerDeals/{dealId}`
*   PUT `/admin/v2/providers/customerDeals/{dealId}`
*   GET `/reports/v2/providers/customers/downloadReportRequests`
*   GET `/reports/v2/providers/category-requests-by-org`
*   GET `/reports/v2/providers/requests-by-category`
*   GET `/admin/v2/organizations`
*   POST `/admin/v2/passwordresets/{customerId}`

### Request

In the `curl` sample:

*   Substitute your Umbrella API key and secret for the value of the `user` option.
*   Set the `X-Umbrella-OrgId` request header with the child organization ID.

```
curl --user '<key>:<secret>' --request POST --url 'https://api.umbrella.com/auth/v2/token' \
-H 'Content-Type: application/x-www-form-urlencoded' \
-H 'X-Umbrella-OrgId: <child organizationId>' \
-d 'grant_type=client_credentials'

```


### Response Schema


|Name        |Type   |Description                                    |
|------------|-------|-----------------------------------------------|
|token_type  |string |The type of access token.                      |
|access_token|string |The OAuth 2.0 access token.                    |
|expires_in  |integer|The number of seconds before the token expires.|


### Response

Sample response (`200`, OK):

```
{
   "token_type": "bearer",
   "access_token": "xxxxxx",
   "expires_in": 3600
}

```


Token Authorization Request for Partner Proof of Value Parent Organizations
---------------------------------------------------------------------------

Use the Umbrella API credentials that you created for your Partner Proof of Value (PPoV) parent organization to generate an API access token for child organizations of PPoV parent organizations.

### API Endpoints Available Only For Partner Proof of Value Parent Organizations

The following API endpoints accept Partner Proof of Value (PPoV) parent organization tokens. Set a child organization ID for the `customerId` path parameter.

*   POST `/reports/v2/providers/customers/{customerId}/securityReportRequests`

### Request

In the `curl` sample:

*   Substitute your Umbrella API key and secret for the value of the `user` option.
*   Set the `X-Umbrella-OrgId` request header with the child organization ID.

```
curl --user '<key>:<secret>' --request POST --url 'https://api.umbrella.com/auth/v2/token' \
-H 'Content-Type: application/x-www-form-urlencoded' \
-H 'X-Umbrella-OrgId: <child organizationId>' \
-d 'grant_type=client_credentials'

```


### Response Schema


|Name        |Type   |Description                                    |
|------------|-------|-----------------------------------------------|
|token_type  |string |The type of access token.                      |
|access_token|string |The OAuth 2.0 access token.                    |
|expires_in  |integer|The number of seconds before the token expires.|


### Response

Sample response (`200`, OK):

```
{
   "token_type": "bearer",
   "access_token": "xxxxxx",
   "expires_in": 3600
}

```


Troubleshooting
---------------

For information about error conditions that may occur when you generate an access token or authorize an Umbrella API request, see [Errors and Troubleshooting](#!umbrella-api-errors-troubleshooting).

Pagination, Rate Limits, and Response Codes
-------------------------------------------

*   For information about how to paginate the Umbrella API collections, see [Pagination](#!umbrella-api-pagination).
*   For information about rate limits that apply to certain Umbrella API endpoints, see [Rate Limits](#!umbrella-api-rate-limits).
*   For information about HTTP response codes, see [Errors and Troubleshooting](#!umbrella-api-errors-troubleshooting).

OAuth 2.0 Scopes
----------------

*   Learn about the Umbrella API OAuth 2.0 scopes. For more information, see [Umbrella OAuth 2.0 Scopes](#!umbrella-api-oauth-scopes).

Samples
-------

We provide code examples, Postman collections, and `curl` samples to help you create your first Umbrella API request.

*   [Sample Scripts](#!umbrella-api-sample-scripts-overview)
*   [Cisco Umbrella Code Samples](https://github.com/CiscoDevNet/cloud-security/tree/master/Umbrella/Samples)
*   [Cisco Umbrella API Postman Examples](https://github.com/CiscoDevNet/cloud-security/tree/master/Umbrella/PostmanExamples)