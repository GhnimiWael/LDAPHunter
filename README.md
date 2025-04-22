# LDAPHunter - LDAP Enumeration Tool

<p align="center">
    <img width="50%" src="https://i.imgur.com/94Xxs6W.png"> 
</p>

```
                                  
                                    _     ____    _    ____    _   _ _   _ _   _ _____ _____ ____  
                                   | |   |  _ \  / \  |  _ \  | | | | | | | \ | |_   _| ____|  _ \ 
                                   | |   | | | |/ _ \ | |_) | | |_| | | | |  \| | | | |  _| | |_) |
                                   | |___| |_| / ___ \|  __/  |  _  | |_| | |\  | | | | |___|  _ < 
                                   |_____|____/_/   \_\_|     |_| |_|\___/|_| \_| |_| |_____|_| \_\
                                                                                                    - @xW43L
                                  
                                              LDAP Enumeration Tool for Pentesters
```

## 1. Overview
This Python tool automates LDAP enumeration for penetration testers, extracting users, groups, organizational units (OUs), password policies, and other critical Active Directory/LDAP information.

### Key Features
- **User Enumeration** – Extract usernames, descriptions, group memberships, and account status  
- **Group Enumeration** – List all groups, members, and highlight privileged groups  
- **OU Enumeration** – Discover organizational units and their descriptions  
- **Password Policy Analysis** – Check password complexity and expiration settings  
- **Unconstrained Delegation Check** – Identify dangerous delegation settings  
- **Hidden Field Extraction** – Display uncommon LDAP fields that may contain sensitive data  

## 2. Installation
### Requirements
- Python 3.x
- `ldap3` and `prettytable` libraries

### Install Dependencies
```bash
pip install ldap3 prettytable
```
## 3. Usage
### Basic Syntax
```bash
python ldap_enum.py -s <SERVER> -d <DOMAIN> [OPTIONS]
```
### Required Arguments

| Argument        | Description                       | Example            |
|-----------------|-----------------------------------|--------------------|
| `-s / --server` | LDAP server IP or hostname        | `-s 10.10.10.100`  |
| `-d / --domain` | Domain name (e.g., domain.local)  | `-d domain.lab`   |

### Authentication Options
#### Option 1: Authenticated Access (Username + Password)
```bash
python ldap_enum.py -s 10.10.11.174 -d domain.lab -u 'domain\user' -P 'P@ssw0rd123!'
```

- `-u / --username`: Username in `DOMAIN\user` or `user@domain` format.
- `-P / --password`: Password (use quotes if special characters exist).

#### Option 2: Anonymous Access (If Allowed)
```bash
python ldap_enum.py -s 10.10.10.100 -d domain.lab --no-auth
```
- `--no-auth`: Attempts anonymous LDAP binding.

#### Option 3: LDAPS (SSL/TLS Encrypted Connection)
```bash
python ldap_enum.py -s 10.10.10.100 -d domain.lab -u 'user@domain.lab' -P 'P@ssw0rd123!' --ssl
```
- `--ssl`: Forces LDAPS (port 636).

### Optional Arguments

| Argument         | Description                  | Example                  |
|------------------|------------------------------|--------------------------|
| `-p / --port`    | LDAP port (default: 389)     | `-p 636`                 |
| `-b / --base-dn` | Manually specify Base DN     | `-b "DC=domain,DC=lab"` |
| `--ssl`          | Use LDAPS (port 636)         | `--ssl`                  |

## 4. Example Output
### User Enumeration
```
[+] Enumerating user accounts...
+----------+----------------+-----------------------------+-------------------+----------+------------------------+-------------------+-------------------+
| Username | Name           | Description                 | Groups            | Disabled | Password Never Expires | Last Logon        | Email             |
+----------+----------------+-----------------------------+-------------------+----------+------------------------+-------------------+-------------------+
| ldap     | LDAP Service   | Service account for LDAP    | Domain Users      | False    | False                  | 2023-10-01 14:30 | ldap@support.htb  |
| admin    | Admin User     | IT Administrator            | Domain Admins     | False    | True                   | 2023-10-02 09:15 | admin@support.htb |
+----------+----------------+-----------------------------+-------------------+----------+------------------------+-------------------+-------------------+

[+] Interesting Findings:
  - Account 'admin' has password set to never expire (security risk!)
  - User 'ldap' has interesting description: "Service account for LDAP"
```

### Uncommon Fields (Potential Sensitive Data)
```
[+] Uncommon Fields with Values:
+----------+-------------------+-----------------------------------+
| Username | Field             | Value                             |
+----------+-------------------+-----------------------------------+
| svc_sql  | info              | "Password: SQL_Admin123"          |
| backup   | notes             | "Temp backup password: B@ckup2023"|
+----------+-------------------+-----------------------------------+
```
### Privileged Groups Found
```
[+] Privileged Groups Found:
  - Domain Admins (2 members)
    Members:
      CN=Admin User,OU=Users,DC=support,DC=htb
      CN=Service Account,OU=Service,DC=support,DC=htb
```

## 5. Troubleshooting
### Common Errors & Fixes

| Error                      | Solution                                                                                                                |
|---------------------------|--------------------------------------------------------------------------------------------------------------------------|
| LDAP error: invalid attribute type | The script now auto-detects valid attributes. If an error persists, manually remove problematic attributes from `extended_attributes` in the script. |
| Connection failed          | Check if LDAP (389) or LDAPS (636) is open (`nc -zv 10.10.11.174 389`). Try `--ssl` if plain LDAP fails.                |
| Anonymous bind failed      | Target likely blocks anonymous LDAP queries. Provide credentials with `-u` and `-P`.                                    |
| Authentication failed      | Verify credentials, try both `DOMAIN\user` and `user@domain` formats.                                                   |


## 6. Security & Legal Considerations
⚠️ Use Responsibly

- Only run against systems you own or have explicit permission to test.
- Credentials are passed in plaintext in memory; avoid using highly privileged accounts.
- Do not store passwords in scripts or logs.
