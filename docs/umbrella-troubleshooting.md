# Cloud Security Response Codes, Errors, Troubleshooting - Cloud Security API - Cisco DevNet
Cloud Security Response Codes, Errors, Troubleshooting

The Umbrella API endpoints raise exceptions when something failed, such as missing or invalid parameters or formatted errors in the request path. We recommend writing code that gracefully handles all possible API exceptions.

Response Codes
--------------

The Umbrella API endpoints use HTTP response codes to indicate success or failure of an API request. In general, codes in the 2xx range indicate success. Codes in the 4xx range indicate an error that resulted from a syntax, name, or format errors. Codes in the 5xx range indicate server errors.



* Status Code: 200
  * Status Message: OK
  * Description: Success. Everything worked as expected.
* Status Code: 201
  * Status Message: Created
  * Description: New resource created.
* Status Code: 202
  * Status Message: Accepted
  * Description: Success. Action is queued.
* Status Code: 204
  * Status Message: No Content
  * Description: Success. Response with no message body.
* Status Code: 400
  * Status Message: Bad Request
  * Description: Likely missing a required parameter or malformed JSON. Review the syntax of your query. Check for any spaces preceding, trailing, or in the domain name of the domain you are trying to query.
* Status Code: 401
  * Status Message: Unauthorized
  * Description: The authorization header is missing or the key and secret pair is invalid. Ensure that your API token is valid.
* Status Code: 403
  * Status Message: Forbidden
  * Description: The client is unauthorized to access the content.
* Status Code: 404
  * Status Message: Not Found
  * Description: The requested resource doesn't exist. Check the syntax of your query or ensure the IP and domain are valid.
* Status Code: 409
  * Status Message: Conflict
  * Description: Exceeded the limit of a list, or attempted to delete an object that is in use.
* Status Code: 429
  * Status Message: Exceeded Limit
  * Description: Too many requests made within a specific time period. You may have exceeded the rate limits for your organization or package.
* Status Code: 500
  * Status Message: Internal Server Error
  * Description: Something wrong with the server.
* Status Code: 503
  * Status Message: Service Unavailable
  * Description: Server is unable to complete request. A dependent service may be temporarily unavailable.


If the response code is not specific enough to determine the cause of the issue, the server includes error messages in the response in JSON format.

Troubleshooting
---------------

Access tokens expire in one hour. You control the expiration date of your API keys.

### API Key Creation

*   You must have Full Admin privileges to create an API key.
*   Check that your Umbrella package includes a license for the Umbrella API and its endpoints.

### API Authentication

Provide your Umbrella API credentials to the Umbrella Token Authorization API to request an Umbrella API access token. An error response may indicate one of the following problems:

*   Your API key may have expired. Update your API key and select a new expiration date.
*   Your API key ID is incorrect or your API key secret is not valid.
*   The format of the API request is not correct.
*   Your request does not include the required request headers, or path and query parameters. For more information, see [Umbrella Authentication](#!umbrella-api-authentication).

Provide your Umbrella API access token with every Umbrella API operation. An error response may indicate one of the following problems:

*   Your Umbrella API access token has expired. Generate a new Umbrella API access token.
*   Your access token does not include the scopes and permissions (**Read Only** or **Read/Write**) for the specific API endpoint.
*   The format of your API request is not correct.
*   Your request does not include the required request headers, or path and query parameters.