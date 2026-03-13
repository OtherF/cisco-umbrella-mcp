# Cloud Security API, Pagination - Cloud Security API - Cisco DevNet
Cloud Security API, Pagination

The Umbrella API endpoints that list a collection also support pagination. Pagination is available for API endpoints within certain scopes.

Admin, Deployments, and Policies
--------------------------------

You can set the `limit` and `page` request query parameters for the collection endpoints.

If you do not set the `limit` query parameter, Umbrella returns up to 200 records per request. The default `page` value is `1`.

Pagination does not apply to the following endpoints:

*   `api.umbrella.com/admin/v2/users`
*   `api.umbrella.com/admin/v2/roles`
*   `api.umbrella.com/deployments/v2/virtualappliances`

Pagination by endpoint:

*   `api.umbrella.com/deployments/v2/networks`
    *   Maximum batch size is 1000 records.
*   `api.umbrella.com/deployments/v2/roamingcomputers`
    *   Maximum batch size is 100 records.
*   `api.umbrella.com/policies/v2/destinationlists/{destinationListId}/destinations`
    *   Maximum batch size is 100 records.

To get another batch size, set the `limit` query parameter. For example:

```
curl -L --location-trusted --request GET --url https://api.umbrella.com/policies/v2/destinationlists/{destinationListId}/destinations?limit=25 \
-H 'Authorization: Bearer %YourAccessToken%' \
-H 'Content-Type: application/json'

```


Investigate
-----------

Many Umbrella Investigate API endpoints provide pagination. Depending on the endpoint, you can set additional query parameters to filter the data in the collection.

The following endpoints support the `limit` and `offset` query parameters:

*   GET `/pdns/name/{domain}`
*   GET `/pdns/domain/{domain}`
*   GET `/pdns/ip/{ip}`
*   GET `/pdns/raw/{anystring}`
*   GET `/whois/emails/{email}`
*   GET `/samples/{domain}`
*   GET `/samples/{ip}`
*   GET `/samples/{url}`
*   GET `/sample/{hash}/artifacts`
*   GET `/sample/{hash}/connections`
*   GET `/sample/{hash}/behaviors`

You can add the `limit` query parameter to these endpoints:

*   GET `/whois/{domain}/history`
*   GET `/whois/nameservers`
*   GET `/topmillion`

> **Note:** If you do not set a limit on the `/topmillion` collection, Umbrella Investigate returns one million records.

Reports
-------

You can control the number of records in the Umbrella Reporting API result set and manage how to read the collection with the `limit` and `offset` query parameters.


|Name  |Type  |Description                                    |
|------|------|-----------------------------------------------|
|offset|number|The index or entry point into the collection.  |
|limit |number|The number of returned items in the collection.|


The Umbrella Reporting API endpoints provide query parameters to filter and customize requests. For more information, see [Umbrella Reporting API Query Parameters](samples/reports/reporting-guide.html).