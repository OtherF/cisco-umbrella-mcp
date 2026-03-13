# Umbrella API Rate Limits - Cloud Security API - Cisco DevNet
Umbrella API Rate Limits

The Umbrella APIs limit the number of requests that you can make within a time period. Rate limits apply to either the number of API requests that you make for your organization or the number of API requests made using a specific Umbrella API key. Rate limits may vary by API scope and resource.

Admin
-----

Endpoints in the `admin` API scope follow these general guidelines for rate limits:

*   5 requests per second
*   14 requests per minute
*   350 requests per 30 minutes

Rate limits apply to an individual API key.

### Rate Limits for Managed Organizations API Endpoints

*   GET `/admin/v2/providers/customerDeals/{dealId}`
*   PUT `/admin/v2/providers/customerDeals/{dealId}`
*   GET `/admin/v2/providers/customers/{customerId}/trialStrengths`
*   GET `/admin/v2/providers/customers/packages`
*   GET `/admin/v2/providers/customerAddresses`
*   POST `/admin/v2/providers/customers/{customerId}/accessRequest`
*   GET `/admin/v2/providers/customers/{customerId}/accessRequest/{accessRequestId}`
*   PUT `/admin/v2/providers/customers/{customerId}/accessRequest/{accessRequestId}`
*   POST `/admin/v2/providers/customers/{customerId}/trialExtensions`
*   GET `/admin/v2/providers/customers/{customerId}/subscriptionDetails`
*   GET `/admin/v2/config/cnames`
*   POST `/admin/v2/config/cnames`
*   GET `/admin/v2/config/cname/{cnameId}`
*   PUT `/admin/v2/config/cname/{cnameId}`
*   DELETE `/admin/v2/config/cname/{cnameId}`
*   GET `/admin/v2/config/contacts`
*   POST `/admin/v2/config/contacts`
*   GET `/admin/v2/config/contact/{contactId}`
*   PUT `/admin/v2/config/contact/{contactId}`
*   DELETE `/admin/v2/config/contact/{contactId}`
*   GET `/admin/v2/config/logos`
*   POST `/admin/v2/config/logos`
*   GET `/admin/v2/config/logos/{logoId}`
*   PUT `/admin/v2/config/logos/{logoId`}
*   DELETE `/admin/v2/config/logos/{logoId}`

The Umbrella Providers and Provider Console Config API endpoints follow these general guidelines for rate limits:

*   30 requests per second
*   70 requests per minute
*   1000 requests per 30 minutes

Rate limits apply to an individual API key.

Auth
----

The Token Authorization API endpoint follows these general guidelines for rate limits:

*   20 requests per minute

Rate limits apply to an individual API key.

Deployments
-----------

API endpoints in the `deployments` API scope except for the Network Tunnels API follow these general guidelines for rate limits:

*   5 requests per second
*   14 requests per minute
*   350 requests per 30 minutes

Rate limits apply to an individual API key.

### Network Tunnels API

The Network Tunnels API endpoints follow these general guidelines for rate limits:

*   3000 requests per minute

Rate limits apply to an individual API key.

Investigate
-----------

The Umbrella Investigate API has four levels of API access:

*   **Integration**—Limited to 2000 requests per day.
*   **Tier 1**
*   **Tier 2**
*   **Tier 3**

Depending on your API access tier, the Umbrella Investigate API limits the number of requests for each endpoint. Your organization's API keys share the same rate limit.

> **Note:** When you exceed the rate limit for an endpoint, all additional requests above the limit receive an `HTTP 429` response (Too Many Requests) and the server discards the requests. After waiting one second, you can retry your request.

### Umbrella Investigate API Endpoints (Group One)

Endpoints:

*   `/domains/volume/{domain}`
*   `/pdns/name/{domain}`
*   `/pdns/domain/{domain}`
*   `/pdns/ip/{ip}`
*   `/pdns/raw/{anystring}`
*   `/recommendations/name/{domain}.json`
*   `/links/name/{domain}`
*   `/security/name/{domain}`
*   `/bgp_routes/asn/{asn}/prefixes_for_asn.json`
*   `/bgp_routes/ip/{ip}/as_for_ip.json`
*   `/topmillion`
*   `/timeline/{name}`
*   `/subdomains/{domain}`

Request Rate Limits:

*   **Integration**—3 requests per second
*   **Tier 1**—3 requests per second
*   **Tier 2**—12 requests per second
*   **Tier 3**—12 requests per second

### Umbrella Investigate API Endpoints (Group Two)

Endpoints:

*   `/samples/{domain}`
*   `/samples/{ip}`
*   `/samples/{url}`
*   `/whois/{domain}`
*   `/whois/{domain}/history`
*   `/whois/nameservers`
*   `/whois/nameservers/{nameservers}`
*   `/whois/emails/{emails}`

Request Rate Limits:

*   **Integration**—3 requests per second.
*   **Tier 1**—3 requests per second.
*   **Tier 2**—12 requests per second.
*   **Tier 3**—48 requests per second.

### POST `/domains/categorization`

API access tiers 2 and 3 support the `/domains/categorization` POST method.

Request Rate Limits:

*   **Tier 2**—150 requests per second
*   **Tier 3**—150 requests per second

> **Note:** The `/domains/categorization` POST method accepts up to 1000 domains in the request body.

### GET `/domains/categorization`

All API access tiers support the `/domains/categorization` GET method.

Request Rate Limits:

*   **Integration**—3 requests per second
*   **Tier 1**—3 requests per second
*   **Tier 2**—150 requests per second
*   **Tier 3**—150 requests per second

### GET `/search/{expression}`

All API access tiers support the `/search/{expression}` endpoint. The `/search/{expression}` endpoint defines rate limits based on search complexity. If you use a wildcard prefix, Umbrella searches the entire collection.

Request Rate Limits:

*   Searches prefixed with the `.*` characters- 3 requests per minute
*   **All other searches**—18 requests per minute

### GET `/whois/search/{searchField}/{regexExpression}`

All API access tiers support the `/whois/search/{searchField}/{regexExpression}` endpoint.

Request Rate Limits:

*   **All tiers**—18 requests per minute

Policies
--------

The Destination Lists API endpoints follow these general guidelines for rate limits:

*   2000 requests per minute
*   6000 requests per hour

Rate limits apply to an individual API key.

Reports
-------

Rate limits of endpoints in the `reports` API scope vary by resource.

### Reporting

The Umbrella Reporting API endpoints follow these general guidelines for rate limits:

*   5 requests per second

Rate limits apply to an Umbrella organization.

### App Discovery

The Umbrella App Discovery API endpoints follow these general guidelines for rate limits:

*   10 requests per second

Rate limits apply to an individual API key.

### API Usage

The Umbrella API Usage Reports API endpoints follow these general guidelines for rate limits:

*   2000 requests per minute
*   6000 requests per hour

Rate limits apply to an individual API key.

### Providers Consoles

The Umbrella Providers Consoles API endpoints follow these general guidelines for rate limits:

*   5 requests per second
*   14 requests per minute
*   350 requests per 30 minutes

Rate limits apply to an individual API key.