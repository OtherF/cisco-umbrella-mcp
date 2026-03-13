# Umbrella API Authentication - Cloud Security API - Cisco DevNet
Umbrella API Authentication

The Cisco Umbrella API provides a standard REST interface and supports the OAuth 2.0 client credentials flow. To get started, log in to Umbrella and create an Umbrella API key.

> **Note:** API keys, passwords, secrets, and tokens allow access to your private customer data. Never share your credentials with another user or organization.

Prerequisites
-------------

*   You must have an Umbrella user account with the **Full Admin** role.

Sign in to Umbrella
-------------------

Sign in to Umbrella at:

[https://dashboard.umbrella.com](https://dashboard.umbrella.com/)

API Key Use Cases
-----------------

You can create various types of API key. The Umbrella Key Admin API enables you to provision and manage Umbrella API keys. Use your Umbrella API keys or legacy Umbrella API keys to create and manage network entities and users, access your reports, manage policies, and integrate your systems and devices with the Cisco Cloud Security platform.



* Key Type: Umbrella API key
  * Description: Secure, intent-based API key with configured scopes and expiration date.
  * Use Cases: View and manage your deployments, users, and policies. View reports and logs.
* Key Type: Legacy Umbrella API key
  * Description: API key that supports access to multiple API resources using Basic authentication. For more information, see Authentication.
  * Use Cases: View and manage your deployments, users, and policies. View reports and logs.
* Key Type: Umbrella Key Admin API key
  * Description: Secure API key with configured permissions and expiration date.
  * Use Cases: View and manage the Umbrella API keys in your organization.


Manage API Keys
---------------

Create and manage Umbrella API keys.

### Create Umbrella API Key

Create an Umbrella API key ID and key secret.

> **Note:** You have only one opportunity to copy your API secret. Umbrella does not save your API secret and you cannot retrieve the secret after its initial creation.

1.  Navigate to **Admin > API Keys** or in a Multi-org, Managed Service Provider (MSP), or Managed Secure Service Provider (MSSP) console navigate to **Console Settings > API Keys**.
    
2.  Click **API Keys** and then click **Add**.
    
    *   The number of expired API keys appears next to the red triangle.
    *   The number of API keys that expire within 30 days appears next to the yellow triangle.
    
    ![Umbrella API key dashboard](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/all-keys-keyadmin-dashboard.png)
3.  Enter a name and description for the key. A name must contain fewer than 256 characters. The description is optional.
    
    ![Umbrella API key name and description](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/umb-add-api-key-name-description.png)
4.  Check the key scopes and expand a key scope to view the scope categories. Check each scope category in a key scope to enable access to the API endpoints. For information about the Umbrella API key scopes, see [OAuth 2.0 Scopes](#!umbrella-api-oauth-scopes).
    
    ![Umbrella API scopes](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/umbrella-api-key-name-desc-update-border.png)
5.  Choose **Read-Only** or **Read / Write** for the selected scope and resource.
    
    ![Umbrella API key scope access](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/selected-api-key-scopes-border.png)
6.  For **Expiry Date**, choose the expiration date for the key, or choose **Never expire**.
    
    ![Umbrella API expiry date](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/keyadmin-create-key-button-border.png)
7.  (Optional) For **Network Restrictions**, enter a comma-separated list of public IP addresses or CIDRs, then click **ADD**.
    
    **Note:** You can add up to ten networks to your API key. You can only use your API key to authenticate requests for clients on the selected networks.
    
    ![Umbrella API network restrictions](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/network-restrictions-umbrella-add-ip.png)
8.  Click **Create Key**.
    
9.  Copy and save your **API Key** and **Key Secret**.
    
10.  Click **Accept And Close**.
     
     ![Umbrella API accept and close](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/api-keys-accept-close.png)

### Refresh Umbrella API Key

Refresh an Umbrella API key ID and key secret.

> **Note:** You have only one opportunity to copy your API secret. Umbrella does not save your API secret and you cannot retrieve the secret after its initial creation.

1.  Navigate to **Admin > API Keys** or in a Multi-org, Managed Service Provider (MSP), or Managed Secure Service Provider (MSSP) console, navigate to **Console Settings > API Keys**.
    
2.  Click **API Keys**, and then expand an API key.
    
3.  Click **Refresh Key**.
    
    ![Umbrella API dashboard](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/api-key-refresh-view-border.png)
4.  Copy and save your **API Key** and **Key Secret**.
    
5.  Click **Accept and Close**.
    
    ![Umbrella API accept and close](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/api-keys-accept-close.png)

### Update Umbrella API Key

Update an Umbrella API key.

1.  Navigate to **Admin > API Keys** or in a Multi-org, Managed Service Provider (MSP), or Managed Secure Service Provider (MSSP) console, navigate to **Console Settings > API Keys**.
    
2.  Click **API Keys**, and then expand an API key. You can modify the **API Key Name**, **Description**, selected scopes and permissions in **Key Scope**, and **Expiry Date**.
    
    ![Umbrella API scope and expiry date](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/umbrella-api-key-name-desc-update-border.png)
3.  For **Network Restrictions**, update the list of IP addresses and CIDRs. Click on the **X** to remove a network address.
    
4.  Click **Save**.
    

### Delete Umbrella API Key

Delete an Umbrella API key.

1.  Navigate to **Admin > API Keys** or in a Multi-org, Managed Service Provider (MSP), or Managed Secure Service Provider (MSSP) console, navigate to **Console Settings > API Keys**.
    
2.  Click **API Keys**, and then expand an API key.
    
3.  Click **Delete**. In the dialog window, click **Delete** to remove the API key from your organization.
    
    ![Umbrella API delete modal](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/api-key-admin-delete-key-border.png)

Manage Key Admin API Keys
-------------------------

Create and manage Umbrella Key Admin API keys.

### Create Key Admin Key

Create a Key Admin API key and secret.

> **Note:** You have only one opportunity to copy your API secret. Umbrella does not save your API secret and you cannot retrieve the secret after its initial creation.

1.  Navigate to **Admin > API Keys** or in a Multi-org, Managed Service Provider (MSP), or Managed Secure Service Provider (MSSP) console navigate to **Console Settings > API Keys**.
    
2.  Click **KeyAdmin Keys**, and then click **Add**.
    
    *   The number of expired API keys appears next to the red triangle.
    *   The number of API keys that expire within 30 days appears next to the yellow triangle.
    
    ![Umbrella API keyAdmin keys dashboard](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/all-keys-keyadmin-dashboard.png)
3.  Enter a name and description for the key. A name must contain fewer than 256 characters. The description is optional.
    
    ![Umbrella API key name and description](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/umb-add-api-key-name-description.png)
4.  Check the permissions for the key.
    
    ![Umbrella API keyAdmin permissions](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/keyadmin-choose-permissions-border.png)
5.  For **Expiry Date**, choose the expiration date for the key, or choose **Never expire**.
    
    ![Umbrella API keyAdmin expiry date](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/keyadmin-create-key-button-border.png)
6.  (Optional) For **Network Restrictions**, enter a comma-separated list of public IP addresses or CIDRs, then click **ADD**.
    
    **Note:** You can add up to ten networks to your API key. You can only use your API key to authenticate requests for clients on the selected networks.
    
    ![Umbrella API network restrictions](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/network-restrictions-umbrella-add-ip.png)
7.  Click **Create Key**.
    
8.  Copy and save your **KeyAdmin Key** and **Key Secret**.
    
9.  Click **Accept And Close**.
    
    ![Umbrella API keyAdmin accept and close dialog](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/api-keys-accept-close.png)

### Refresh Key Admin Key

Refresh a Key Admin API key and secret.

> **Note:** You have only one opportunity to copy your API secret. Umbrella does not save your API secret and you cannot retrieve the secret after its initial creation.

1.  Navigate to **Admin > API Keys** or in a Multi-org, Managed Service Provider (MSP), or Managed Secure Service Provider (MSSP) console navigate to **Console Settings > API Keys**.
    
2.  Click **KeyAdmin Keys**, and then expand an API key.
    
    ![Umbrella API Key Admin keys dashboard](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/all-keys-keyadmin-dashboard.png)
3.  Click **Refresh Key**.
    
    ![Umbrella Key Admin API refresh](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/keyadmin-refresh-key-border.png)
4.  Copy and save your **KeyAdmin Key** and **Key Secret**.
    
5.  Click **Accept and Close**.
    
    ![Umbrella keyAdmin API accept and close dialog](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/api-keys-accept-close.png)

### Update Key Admin Key

Update a Key Admin API key.

1.  Navigate to **Admin > API Keys** or in a Multi-org, Managed Service Provider (MSP), or Managed Secure Service Provider (MSSP) console navigate to **Console Settings > API Keys**.
    
    ![Umbrella keyAdmin API keys dashboard](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/all-keys-keyadmin-dashboard.png)
2.  Click **KeyAdmin Keys**, and then expand an API key. You can modify the **Key Admin Key Name**, **Description**, **Permissions**, **Expiry Date**, and **Network Restrictions**.
    
    ![Umbrella API Key Admin permissions](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/keyadmin-choose-permissions-border.png)
3.  Click **Save**.
    

### Delete Key Admin Key

Delete a Key Admin API key.

1.  Navigate to **Admin > API Keys** or in a Multi-org, Managed Service Provider (MSP), or Managed Secure Service Provider (MSSP) console navigate to **Console Settings > API Keys**.
    
    ![Umbrella keyAdmin API keys dashboard](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/all-keys-keyadmin-dashboard.png)
2.  Click **KeyAdmin Keys**, and then expand an API key.
    
3.  Click **Delete**. In the dialog window, click **Delete** to remove the API key from your organization.
    
    ![Umbrella keyAdmin API delete](https://pubhub.devnetcloud.com/media/cloud-security-apis-in-eft/docs/images/api-key-admin-delete-key-border.png)