# Cloud Security API, Umbrella OAuth 2.0, API key scopes - Cloud Security API - Cisco DevNet
Cloud Security API, Umbrella OAuth 2.0, API key scopes

You can create API keys with **Read-Only** or **Read/Write** permissions for any number of Umbrella resources. Umbrella groups the resources into these scopes: `admin`, `deployments`, `investigate`, `policies`, and `reports`.

For information about creating your API credentials, see [Authentication](#!umbrella-api-authentication).

Admin Scopes and Endpoints
--------------------------

Choose the `admin:read` scope to retrieve the Admin resources in your organization.

Choose the `admin:write` scope to create, manage, or remove an Admin resource in your organization.

The Admin OAuth 2.0 scope includes these resources:

*   [ApiKeys](#!umbrella-api-oauth-scopes/apikeys)
*   [Users](#!umbrella-api-oauth-scopes/users)
*   [Roles](#!umbrella-api-oauth-scopes/roles)
*   [S3 Bucket Key Rotation](#!umbrella-api-oauth-scopes/s3-bucket-key-rotation)

### ApiKeys


|Scope                |Description        |Endpoints                                |
|---------------------|-------------------|-----------------------------------------|
|admin.apikeys:delete |Delete an API key. |DELETE /admin/v2/apiKeys/{apiKeyId}      |
|admin.apikeys:update |Update an API key. |PATCH /admin/v2/apiKeys/{apiKeyId}       |
|admin.apikeys:refresh|Refresh an API key.|POST /admin/v2/apiKeys/{apiKeyId}/refresh|
|admin.apikeys:read   |View an API key.   |GET /admin/v2/apiKeys                    |
|                     |                   |GET /admin/v2/apiKeys/{apiKeyId}         |
|admin.apikeys:create |Create an API key. |POST /admin/v2/apiKeys                   |


### Users


|Scope            |Description                         |Endpoints                      |
|-----------------|------------------------------------|-------------------------------|
|admin.users:read |View the user accounts.             |GET /admin/v2/users            |
|                 |                                    |GET /admin/v2/users/{userId}   |
|admin.users:write|Create and delete the user accounts.|POST /admin/v2/users           |
|                 |                                    |DELETE /admin/v2/users/{userId}|


### Roles


|Scope           |Description         |Endpoints          |
|----------------|--------------------|-------------------|
|admin.roles:read|View the user roles.|GET /admin/v2/roles|


### S3 Bucket Key Rotation


|Scope          |Description                            |Endpoints                   |
|---------------|---------------------------------------|----------------------------|
|admin.iam:write|Rotate the Cisco-managed S3 bucket key.|POST /admin/v2/iam/rotateKey|


Admin Scopes and Endpoints for Managed Organizations
----------------------------------------------------

Choose the `admin:read` scope to retrieve the Admin resources in your organization.

Choose the `admin:write` scope to create, manage, or remove an Admin resource in your organization.

The Admin OAuth 2.0 scope for managed organizations includes these resources:

*   [Password Reset](#!umbrella-api-oauth-scopes/password-reset)
*   [Organizations](#!umbrella-api-oauth-scopes/organizations)
*   [Customers](#!umbrella-api-oauth-scopes/customers)
*   [Customer Search](#!umbrella-api-oauth-scopes/customer-search)
*   [Customer Deals](#!umbrella-api-oauth-scopes/customer-deals)
*   [Config](#!umbrella-api-oauth-scopes/config)

### Password Reset



* Scope: admin.passwordreset:write
  * Description: Update the customer's password.
  * Endpoints: POST /admin/v2/passwordResets/{customerId}


### Organizations


|Scope                   |Description            |Endpoints                  |
|------------------------|-----------------------|---------------------------|
|admin.organizations:read|View the organizations.|GET /admin/v2/organizations|


### Customers



* Scope: admin.customers:read
  * Description: View the customers.
  * Endpoints: GET /admin/v2/providers/customers
* Scope: 
  * Description: 
  * Endpoints: GET /admin/v2/providers/customers/{customerId}
* Scope: 
  * Description: 
  * Endpoints: GET /admin/v2/providers/customers/{customerId}/accessRequests/{accessRequestId}
* Scope: 
  * Description: 
  * Endpoints: GET /admin/v2/providers/customers/{customerId}/trialStrengths
* Scope: 
  * Description: 
  * Endpoints: GET /admin/v2/providers/customers/packages
* Scope: 
  * Description: 
  * Endpoints: GET /admin/v2/managed/customers
* Scope: 
  * Description: 
  * Endpoints: GET /admin/v2/managed/customers/{customerId}
* Scope: admin.customers:write
  * Description: Create, update, and delete the customers.
  * Endpoints: POST /admin/v2/providers/customers
* Scope: 
  * Description: 
  * Endpoints: DELETE /admin/v2/providers/customers/{customerId}
* Scope: 
  * Description: 
  * Endpoints: PUT /admin/v2/providers/customers/{customerId}
* Scope: 
  * Description: 
  * Endpoints: PUT /admin/v2/providers/customers/{customerId}/trialconversions
* Scope: 
  * Description: 
  * Endpoints: POST /admin/v2/providers/customers/{customerId}/accessRequests
* Scope: 
  * Description: 
  * Endpoints: PUT /admin/v2/providers/customers/{customerId}/accessRequests/{accessRequestId}
* Scope: 
  * Description: 
  * Endpoints: POST /admin/v2/managed/customers
* Scope: 
  * Description: 
  * Endpoints: DELETE /admin/v2/managed/customers/{customerId}
* Scope: 
  * Description: 
  * Endpoints: PUT /admin/v2/managed/customers/{customerId}


### Customer Search



* Scope: admin.customerSearch:read
  * Description: List the customers by the email addresses.
  * Endpoints: GET /admin/v2/providers/customerAddresses


### Customer Deals



* Scope: admin.customerdeals:read
  * Description: View the customer deals.
  * Endpoints: GET /admin/v2/providers/customerDeals/{dealId}
* Scope: admin.customerdeals:write
  * Description: Update the customer deals.
  * Endpoints: PUT /admin/v2/providers/customerDeals/{dealId}


### Config



* Scope: admin.config:read
  * Description: View the configured logos, cnames, and contacts.
  * Endpoints: GET /admin/v2/config/cnames
* Scope: 
  * Description: 
  * Endpoints: GET /admin/v2/config/cnames/{cnameId}
* Scope: 
  * Description: 
  * Endpoints: GET /admin/v2/config/contacts
* Scope: 
  * Description: 
  * Endpoints: GET /admin/v2/config/contacts/{contactId}
* Scope: 
  * Description: 
  * Endpoints: GET /admin/v2/config/logos/{logoId}
* Scope: 
  * Description: 
  * Endpoints: GET /admin/v2/config/logos
* Scope: admin.config:write
  * Description: Create, update, and delete the configured logos, cnames, and contacts.
  * Endpoints: POST /admin/v2/config/cnames
* Scope: 
  * Description: 
  * Endpoints: PUT /admin/v2/config/cnames/{cnameId}
* Scope: 
  * Description: 
  * Endpoints: DELETE /admin/v2/config/cnames/{cnameId}
* Scope: 
  * Description: 
  * Endpoints: POST /admin/v2/config/contacts
* Scope: 
  * Description: 
  * Endpoints: PUT /admin/v2/config/contacts/{contactId}
* Scope: 
  * Description: 
  * Endpoints: DELETE /admin/v2/config/contacts/{contactId}
* Scope: 
  * Description: 
  * Endpoints: POST /admin/v2/config/logos
* Scope: 
  * Description: 
  * Endpoints: PUT /admin/v2/config/logos/{logoId}
* Scope: 
  * Description: 
  * Endpoints: DELETE /admin/v2/config/logos/{logoId}


Deployments Scopes and Endpoints
--------------------------------

Choose the `deployments:read` scope to retrieve the Deployments resources in your organization.

Choose the `deployments:write` scope to create, manage, or remove a Deployments resource in your organization.

The Deployments OAuth 2.0 scope includes these resources:

*   [Networks](#!umbrella-api-oauth-scopes/networks)
*   [Internal Networks](#!umbrella-api-oauth-scopes/internal-networks)
*   [Internal Domains](#!umbrella-api-oauth-scopes/internal-domains)
*   [Data Centers](#!umbrella-api-oauth-scopes/data-centers)
*   [Network Tunnels](#!umbrella-api-oauth-scopes/network-tunnels)
*   [Roaming Computers](#!umbrella-api-oauth-scopes/roaming-computers)
*   [OrgInfo for Roaming Computers](#!umbrella-api-oauth-scopes/orginfo-for-roaming-computers)
*   [Tags](#!umbrella-api-oauth-scopes/tags)
*   [Tagged Devices](#!umbrella-api-oauth-scopes/tagged-devices)
*   [Policies](#!umbrella-api-oauth-scopes/policies)
*   [Sites](#!umbrella-api-oauth-scopes/sites)
*   [Virtual Appliances](#!umbrella-api-oauth-scopes/virtual-appliances)
*   [Network Devices](#!umbrella-api-oauth-scopes/network-devices)
*   [Secure Web Gateway Device Settings](#!umbrella-api-oauth-scopes/secure-web-gateway-device-settings)

### Networks



* Scope: deployments.networks:read
  * Description: View the networks.
  * Endpoints: GET /deployments/v2/networks
* Scope: 
  * Description: 
  * Endpoints: GET /deployments/v2/networks/{networkId}
* Scope: 
  * Description: 
  * Endpoints: GET /deployments/v2/networks/{networkId}/policies
* Scope: deployments.networks:write
  * Description: Create, update, and delete the networks.
  * Endpoints: POST /deployments/v2/networks
* Scope: 
  * Description: 
  * Endpoints: PUT /deployments/v2/networks/{networkId}
* Scope: 
  * Description: 
  * Endpoints: DELETE /deployments/v2/networks/{networkId}


### Internal Networks



* Scope: deployments.internalnetworks:read
  * Description: View the internal networks.
  * Endpoints: GET /deployments/v2/internalnetworks
* Scope: 
  * Description: 
  * Endpoints: GET /deployments/v2/internalnetworks/{internalNetworkId}
* Scope: 
  * Description: 
  * Endpoints: GET /deployments/v2/internalnetworks/{internalNetworkId}/policies
* Scope: deployments.internalnetworks:write
  * Description: Create, update, and delete the internal networks.
  * Endpoints: POST /deployments/v2/internalnetworks
* Scope: 
  * Description: 
  * Endpoints: PUT /deployments/v2/internalnetworks/{internalNetworkId}
* Scope: 
  * Description: 
  * Endpoints: DELETE /deployments/v2/internalnetworks/{internalNetworkId}


### Internal Domains



* Scope: deployments.internaldomains:read
  * Description: View the internal domains.
  * Endpoints: GET /deployments/v2/internaldomains
* Scope: 
  * Description: 
  * Endpoints: GET /deployments/v2/internaldomains/{internalDomainId}
* Scope: deployments.internaldomains:write
  * Description: Create, update, and delete the internal domains.
  * Endpoints: POST /deployments/v2/internaldomains
* Scope: 
  * Description: 
  * Endpoints: PUT /deployments/v2/internaldomains/{internalDomainId}
* Scope: 
  * Description: 
  * Endpoints: DELETE /deployments/v2/internaldomains/{internalDomainId}


### Data Centers



* Scope: deployments.datacenters:read
  * Description: View the data centers for the network tunnels.
  * Endpoints: GET /deployments/v2/datacenters


### Network Tunnels



* Scope: deployments.tunnels:read
  * Description: View the network tunnels.
  * Endpoints: GET /deployments/v2/tunnels
* Scope: 
  * Description: 
  * Endpoints: GET /deployments/v2/tunnels/{id}
* Scope: 
  * Description: 
  * Endpoints: GET /deployments/v2/tunnels/{id}/policies
* Scope: 
  * Description: 
  * Endpoints: GET /deployments/v2/tunnelsState
* Scope: 
  * Description: 
  * Endpoints: GET /deployments/v2/tunnels/{id}/state
* Scope: 
  * Description: 
  * Endpoints: GET /deployments/v2/tunnels/{id}/events
* Scope: 
  * Description: 
  * Endpoints: GET /deployments/v2/tunnels/{id}/globalEvents/sourceIp/{ip}
* Scope: deployments.tunnels:write
  * Description: Create, update, and delete the network tunnels.
  * Endpoints: POST /deployments/v2/tunnels
* Scope: 
  * Description: 
  * Endpoints: PUT /deployments/v2/tunnels/{id}
* Scope: 
  * Description: 
  * Endpoints: DELETE /deployments/v2/tunnels/{id}
* Scope: 
  * Description: 
  * Endpoints: POST /deployments/v2/tunnels/{id}/keys


### Roaming Computers



* Scope: deployments.roamingcomputers:read
  * Description: View the roaming computers.
  * Endpoints: GET /deployments/v2/roamingcomputers
* Scope: 
  * Description: 
  * Endpoints: GET /deployments/v2/roamingcomputers/{deviceId}
* Scope: deployments.roamingcomputers:write
  * Description: View, update, and delete the roaming computers.
  * Endpoints: PUT /deployments/v2/roamingcomputers/{deviceId}
* Scope: 
  * Description: 
  * Endpoints: DELETE /deployments/v2/roamingcomputers/{deviceId}


### OrgInfo for Roaming Computers



* Scope: deployments.roamingcomputersOrgInfo:read
  * Description: View the OrgInfo.json properties for roaming computers.
  * Endpoints: GET /deployments/v2/roamingcomputers/orgInfo


### Tags


|Scope                 |Description     |Endpoints                |
|----------------------|----------------|-------------------------|
|deployments.tags:read |View the tags.  |GET /deployments/v2/tags |
|deployments.tags:write|Create the tags.|POST /deployments/v2/tags|


### Tagged Devices



* Scope: deployments.tagDevices:read
  * Description: View the tagged devices.
  * Endpoints: GET /deployments/v2/tags/{tagId}/devices
* Scope: deployments.tagDevices:write
  * Description: Create and delete the tagged devices.
  * Endpoints: POST /deployments/v2/tags/{tagId}/devices
* Scope: 
  * Description: 
  * Endpoints: DELETE /deployments/v2/tags/{tagId}/devices


### Policies



* Scope: deployments.policies:read
  * Description: View the policies for the deployments.
  * Endpoints: GET /deployments/v2/policies
* Scope: deployments.policies:write
  * Description: Update and delete the policies for the deployments.
  * Endpoints: PUT /deployments/v2/policies/{policyId}/identities/{originId}
* Scope: 
  * Description: 
  * Endpoints: DELETE /deployments/v2/policies/{policyId}/identities/{originId}


### Sites



* Scope: deployments.sites:read
  * Description: View the sites.
  * Endpoints: GET /deployments/v2/sites
* Scope: 
  * Description: 
  * Endpoints: GET /deployments/v2/sites/{siteId}
* Scope: deployments.sites:write
  * Description: Create, update, and delete the sites.
  * Endpoints: POST /deployments/v2/sites
* Scope: 
  * Description: 
  * Endpoints: PUT /deployments/v2/sites/{siteId}
* Scope: 
  * Description: 
  * Endpoints: DELETE /deployments/v2/sites/{siteId}


### Virtual Appliances



* Scope: deployments.virtualappliances:read
  * Description: View the virtual appliances.
  * Endpoints: GET /deployments/v2/virtualappliances
* Scope: 
  * Description: 
  * Endpoints: GET /deployments/v2/virtualappliances/{virtualApplianceId}
* Scope: deployments.virtualappliances:write
  * Description: Update and delete the virtual appliances.
  * Endpoints: PUT /deployments/v2/virtualappliances/{virtualApplianceId}
* Scope: 
  * Description: 
  * Endpoints: DELETE /deployments/v2/virtualappliances/{virtualApplianceId}


### Network Devices



* Scope: deployments.networkdevices:read
  * Description: View the network devices.
  * Endpoints: GET /deployments/v2/networkdevices
* Scope: 
  * Description: 
  * Endpoints: GET /deployments/v2/networkdevices/{originId}
* Scope: deployments.networkdevices:write
  * Description: Create, update, and delete the network devices.
  * Endpoints: POST /deployments/v2/networkdevices
* Scope: 
  * Description: 
  * Endpoints: PATCH /deployments/v2/networkdevices/{originId}
* Scope: 
  * Description: 
  * Endpoints: DELETE /deployments/v2/networkdevices/{originId}


### Secure Web Gateway Device Settings



* Scope: deployments.devices.swg:read
  * Description: View the secure web gateway override settings on the devices.
  * Endpoints: POST /deployments/v2/deviceSettings/SWGEnabled/list
* Scope: deployments.devices.swg:write
  * Description: Update and delete secure web gateway settings on the devices.
  * Endpoints: POST /deployments/v2/deviceSettings/SWGEnabled/set
* Scope: 
  * Description: 
  * Endpoints: POST /deployments/v2/deviceSettings/SWGEnabled/remove


Investigate Scopes and Endpoints
--------------------------------

Choose the `investigate:read` scope to retrieve the Investigate resources in your organization.

Choose the `investigate.bulk:read` scope to retrieve the Investigate bulk resources in your organization.

The Investigate OAuth 2.0 scope includes these resources:

*   [Investigate](#!umbrella-api-oauth-scopes/investigate)
*   [Investigate Bulk](#!umbrella-api-oauth-scopes/investigate-bulk)

### Investigate



* Scope: investigate.investigate:read
  * Description: View the information about a domain.
  * Endpoints: GET /investigate/v2/domains/categorization/{domain}
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/domains/volume/{domain}
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/recommendations/name/{domain}.json
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/pdns/name/{domain}
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/pdns/domain/{domain}
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/pdns/ip/{ip}
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/pdns/raw/{anystring}
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/links/name/{domain}
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/security/name/{domain}
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/domains/risk-score/{domain}
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/bgp_routes/ip/{ip}/as_for_ip.json
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/bgp_routes/asn/{asn}/prefixes_for_asn.json
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/whois/{domain}
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/whois/{domain}/history
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/whois/nameservers/{nameserver}
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/whois/nameservers
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/whois/emails/{email}
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/whois/search/{searchField}/{regexExpression}
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/search/{expression}
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/topmillion
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/samples/{destination}
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/sample/{hash}
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/sample/{hash}/artifacts
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/sample/{hash}/connections
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/sample/{hash}/behaviors
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/timeline/{name}
* Scope: 
  * Description: 
  * Endpoints: GET /investigate/v2/subdomains/{domain}


### Investigate Bulk



* Scope: investigate.bulk:read
  * Description: View the information about multiple domains.
  * Endpoints: POST /investigate/v2/domains/categorization


Policies Scopes and Endpoints
-----------------------------

Choose the `policies:read` scope to retrieve the Policies resources in your organization.

Choose the `policies:write` scope to create, manage, or remove a Policies resource in your organization.

The Policies OAuth 2.0 scope includes these resources:

*   [Destination Lists](#!umbrella-api-oauth-scopes/destination-lists)
*   [Destinations](#!umbrella-api-oauth-scopes/destinations)
*   [Application Lists](#!umbrella-api-oauth-scopes/application-lists)

### Destination Lists



* Scope: policies.destinationLists:read
  * Description: View the destination lists.
  * Endpoints: GET /policies/v2/destinationlists
* Scope: 
  * Description: 
  * Endpoints: GET /policies/v2/destinationlists/{destinationListId}
* Scope: policies.destinationLists:write
  * Description: Create, update, and delete a destination list.
  * Endpoints: POST /policies/v2/destinationlists
* Scope: 
  * Description: 
  * Endpoints: PATCH /policies/v2/destinationlists/{destinationListId}
* Scope: 
  * Description: 
  * Endpoints: DELETE /policies/v2/destinationlists/{destinationListId}


### Destinations



* Scope: policies.destinations:read
  * Description: View the destinations in a destination list.
  * Endpoints: GET /policies/v2/destinationlists/{destinationListId}/destinations
* Scope: policies.destinations:write
  * Description: Add and delete destinations in a destination list.
  * Endpoints: POST /policies/v2/destinationlists/{destinationListId}/destinations
* Scope: 
  * Description: 
  * Endpoints: DELETE /policies/v2/destinationlists/{destinationListId}/destinations/remove


### Application Lists



* Scope: policies.applicationlists:read
  * Description: View the application lists.
  * Endpoints: GET /policies/v2/applicationLists
* Scope: 
  * Description: 
  * Endpoints: GET /policies/v2/applications/usage
* Scope: policies.applicationlists:write
  * Description: Create, update, and delete the application lists.
  * Endpoints: POST /policies/v2/applicationLists
* Scope: 
  * Description: 
  * Endpoints: PUT /policies/v2/applicationLists/{applicationListId}
* Scope: 
  * Description: 
  * Endpoints: DELETE /policies/v2/applicationLists/{applicationListId}


Reports Scopes and Endpoints
----------------------------

Choose the `reports:read` scope to retrieve Reports resources in your organization.

Choose the `reports:write` scope to create, manage, or remove a Reports resource in your organization.

The Reports OAuth 2.0 scope includes these resources:

*   [Aggregations](#!umbrella-api-oauth-scopes/aggregations)
*   [Granular Events](#!umbrella-api-oauth-scopes/granular-events)
*   [Summaries by Rule](#!umbrella-api-oauth-scopes/summaries-by-rule)
*   [Utilities](#!umbrella-api-oauth-scopes/utilities)
*   [App Discovery](#!umbrella-api-oauth-scopes/app-discovery)
*   [API Usage](#!umbrella-api-oauth-scopes/api-usage)

### Aggregations



* Scope: reports.aggregations:read
  * Description: View the aggregated events.
  * Endpoints: GET /reports/v2/top-identities
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/top-identities/{type}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/identity-distribution
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/identity-distribution/{type}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/top-destinations
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/top-destinations/{type}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/top-urls
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/top-categories
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/top-categories/{type}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/top-eventtypes
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/top-dns-query-types
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/top-files
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/total-requests
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/total-requests/{type}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/top-threats
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/top-threats/{type}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/top-threat-types
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/top-threat-types/{type}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/top-ips
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/top-ips/internal
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/summary
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/summary/{type}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/summaries-by-category
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/summaries-by-category/{type}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/summaries-by-destination
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/summaries-by-destination/{type}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/requests-by-hour
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/requests-by-hour/{type}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/requests-by-timerange
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/requests-by-timerange/{type}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/categories-by-hour
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/categories-by-hour/{type}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/categories-by-timerange
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/categories-by-timerange/{type}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/deployment-status
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/bandwidth-by-hour
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/bandwidth-by-timerange


### Granular Events


|Scope                      |Description              |Endpoints                                 |
|---------------------------|-------------------------|------------------------------------------|
|reports.granularEvents:read|View the granular events.|GET /reports/v2/activity                  |
|                           |                         |GET /reports/v2/activity/dns              |
|                           |                         |GET /reports/v2/activity/proxy            |
|                           |                         |GET /reports/v2/activity/firewall         |
|                           |                         |GET /reports/v2/activity/intrusion        |
|                           |                         |GET /reports/v2/activity/ip               |
|                           |                         |GET /reports/v2/activity/amp-retrospective|


### Summaries By Rule



* Scope: reports.summariesByRule:read
  * Description: View the summaries by rules events.
  * Endpoints: GET /reports/v2/summaries-by-rule/intrusion


### Utilities



* Scope: reports.utilities:read
  * Description: View the reference information for the reports.
  * Endpoints: GET /reports/v2/applications
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/categories
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/identities
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/identities/{identityid}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/threat-types
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/threat-types/{threattypeid}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/threat-names
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/threat-names/{threatnameid}
* Scope: 
  * Description: 
  * Endpoints: POST /reports/v2/identities


### App Discovery



* Scope: reports.appDiscovery:read
  * Description: View the application discovery events.
  * Endpoints: GET /reports/v2/appDiscovery/applications
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/appDiscovery/applications/{applicationId}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/appDiscovery/applications/{applicationId}/risk
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/appDiscovery/applications/{applicationId}/identities
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/appDiscovery/applications/{applicationId}/attributes
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/appDiscovery/protocols
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/appDiscovery/protocols/{protocolId}
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/appDiscovery/protocols/{protocolId}/identities
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/appDiscovery/applicationCategories
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/appDiscovery/applications/info
* Scope: reports.appDiscovery:write
  * Description: Update the label for the applications.
  * Endpoints: PATCH /reports/v2/appDiscovery/applications
* Scope: 
  * Description: 
  * Endpoints: PATCH /reports/v2/appDiscovery/applications/{applicationId}


### API Usage


|Scope                |Description            |Endpoints                         |
|---------------------|-----------------------|----------------------------------|
|reports.apiusage:read|View the API key usage.|GET /reports/v2/apiUsage/requests |
|                     |                       |GET /reports/v2/apiUsage/responses|
|                     |                       |GET /reports/v2/apiUsage/keys     |
|                     |                       |GET /reports/v2/apiUsage/summary  |


Reports Scopes and Endpoints for Managed Organizations
------------------------------------------------------

Choose the `reports:read` scope to retrieve the Reports resources in your managed organization.

Choose the `reports:write` scope to create, manage, or remove a Reports resource in your managed organization.

The Reports OAuth 2.0 scope for managed organizations includes these resources:

*   [Utilities](#!umbrella-api-oauth-scopes/utilities)
*   [Customers](#!umbrella-api-oauth-scopes/customers)

### Utilities



* Scope: reports.utilities:read
  * Description: View the reference information for the reports.
  * Endpoints: GET /reports/v2/providers/categories


### Customers



* Scope: reports.customers:read
  * Description: View the events for the customers.
  * Endpoints: GET /reports/v2/providers/deployments
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/providers/requests-by-hour
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/providers/requests-by-timerange
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/providers/requests-by-org
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/providers/requests-by-category
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/providers/requests-by-destination
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/providers/category-requests-by-org
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/providers/category-requests-by-org
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/providers/consoles
* Scope: 
  * Description: 
  * Endpoints: GET /reports/v2/providers/customers/downloadReportRequests
* Scope: reports.customers:write
  * Description: View the events by the request types.
  * Endpoints: POST /reports/v2/providers/customers/{customerId}/securityReportRequests
