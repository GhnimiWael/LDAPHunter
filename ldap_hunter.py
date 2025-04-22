#!/usr/bin/env python3
import ldap3
import argparse
from ldap3.core.exceptions import LDAPException, LDAPBindError
from prettytable import PrettyTable
import sys

def print_banner():
    banner = r"""

  _     ____    _    ____    _   _ _   _ _   _ _____ _____ ____  
 | |   |  _ \  / \  |  _ \  | | | | | | | \ | |_   _| ____|  _ \ 
 | |   | | | |/ _ \ | |_) | | |_| | | | |  \| | | | |  _| | |_) |
 | |___| |_| / ___ \|  __/  |  _  | |_| | |\  | | | | |___|  _ < 
 |_____|____/_/   \_\_|     |_| |_|\___/|_| \_| |_| |_____|_| \_\
                                                                  - @xW43L

          LDAP Enumeration Tool for Pentesters
"""
    print(banner)

def parse_arguments():
    parser = argparse.ArgumentParser(description='LDAP Enumeration Tool for Pentesters')
    parser.add_argument('-s', '--server', required=True, help='LDAP server IP or hostname')
    parser.add_argument('-p', '--port', type=int, default=389, help='LDAP port (default: 389)')
    parser.add_argument('-d', '--domain', required=True, help='Domain name (e.g., domain.local)')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-P', '--password', help='Password for authentication')
    parser.add_argument('-b', '--base-dn', help='Base DN for LDAP queries (auto-detected if not provided)')
    parser.add_argument('--ssl', action='store_true', help='Use SSL/TLS')
    parser.add_argument('--no-auth', action='store_true', help='Attempt anonymous bind')
    return parser.parse_args()

def get_ldap_connection(args):
    server = ldap3.Server(args.server, port=args.port, use_ssl=args.ssl, get_info=ldap3.ALL)
    
    if args.no_auth:
        try:
            conn = ldap3.Connection(server, auto_bind=True)
            print("[+] Successfully bound anonymously")
            return conn
        except LDAPBindError as e:
            print(f"[-] Anonymous bind failed: {e}")
            sys.exit(1)
    else:
        if not args.username or not args.password:
            print("[-] Username and password required for authenticated bind")
            sys.exit(1)
        
        username = args.username if '@' in args.username else f"{args.username}@{args.domain}"
        try:
            conn = ldap3.Connection(server, user=username, password=args.password, auto_bind=True)
            print(f"[+] Successfully authenticated as {username}")
            return conn
        except LDAPBindError as e:
            print(f"[-] Authentication failed: {e}")
            sys.exit(1)

def get_base_dn(conn, domain):
    # Try to auto-detect base DN if not provided
    domain_parts = domain.split('.')
    base_dn = ','.join([f'dc={part}' for part in domain_parts])
    
    # Verify the base DN is valid
    try:
        conn.search(base_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['*'])
        return base_dn
    except LDAPException:
        print(f"[-] Could not auto-detect base DN. Please provide with -b option")
        sys.exit(1)

def enumerate_users(conn, base_dn):
    print("\n[+] Enumerating user accounts...")
    # Standard attributes we always want to see
    standard_attributes = [
        'sAMAccountName', 'name', 'displayName', 'description', 
        'memberOf', 'userAccountControl', 'lastLogon', 'pwdLastSet',
        'mail', 'title', 'department', 'manager'
    ]
    
    # Additional interesting attributes that might exist
    extended_attributes = [
        'info', 'notes', 'comment', 'userPassword', 'unixUserPassword',
        'logonCount', 'badPwdCount', 'whenCreated', 'whenChanged',
        'scriptPath', 'homeDirectory', 'adminCount', 'servicePrincipalName'
    ]
    
    # First check which extended attributes actually exist
    valid_attributes = standard_attributes.copy()
    for attr in extended_attributes:
        try:
            # Test attribute by doing a minimal query
            conn.search(base_dn, '(objectClass=user)', search_scope=ldap3.SUBTREE,
                      attributes=[attr], size_limit=1)
            valid_attributes.append(attr)
        except LDAPException:
            print(f"  [!] Attribute {attr} not available on this server")
    
    # Now do the full query with only valid attributes
    conn.search(
        search_base=base_dn,
        search_filter='(&(objectClass=user)(sAMAccountName=*))',
        search_scope=ldap3.SUBTREE,
        attributes=valid_attributes
    )
    
    if not conn.entries:
        print("[-] No user accounts found")
        return
    
    # Display standard info in pretty table
    user_table = PrettyTable()
    user_table.field_names = [
        "Username", "Name", "Description", "Groups", "Disabled", 
        "Password Never Expires", "Last Logon", "Email"
    ]
    user_table.align = "l"
    user_table.max_width = 30
    
    for entry in conn.entries:
        username = entry.sAMAccountName.value if 'sAMAccountName' in entry else "N/A"
        name = entry.name.value if 'name' in entry else "N/A"
        description = entry.description.value if 'description' in entry else "N/A"
        groups = ", ".join(entry.memberOf) if 'memberOf' in entry else "N/A"
        email = entry.mail.value if 'mail' in entry else "N/A"
        
        # Decode userAccountControl flags
        uac = entry.userAccountControl.value if 'userAccountControl' in entry else 0
        disabled = bool(uac & 0x0002)
        pwd_never_expires = bool(uac & 0x10000)
        
        # Convert lastLogon timestamp if available
        last_logon = "N/A"
        if 'lastLogon' in entry and entry.lastLogon.value:
            last_logon = str(entry.lastLogon.value)
        
        user_table.add_row([
            username, name, description, groups, 
            disabled, pwd_never_expires, last_logon, email
        ])
    
    print(user_table)
    
    # Display interesting findings from standard fields
    print("\n[+] Interesting Findings from Standard Fields:")
    for entry in conn.entries:
        if 'description' in entry and entry.description.value:
            desc = entry.description.value.lower()
            if any(keyword in desc for keyword in ['password', 'admin', 'test', 'temp', 'backup']):
                print(f"  - User '{entry.sAMAccountName.value}' has interesting description: {entry.description.value}")
        
        if 'userAccountControl' in entry:
            uac = entry.userAccountControl.value
            if uac & 0x0002:  # Disabled account
                print(f"  - Account '{entry.sAMAccountName.value}' is disabled")
            if uac & 0x10000:  # Password never expires
                print(f"  - Account '{entry.sAMAccountName.value}' has password set to never expire")
            if not (uac & 0x0002) and (uac & 0x10000):  # Enabled account with password never expires
                print(f"  - WARNING: Active account '{entry.sAMAccountName.value}' has password set to never expire")

    # Display uncommon fields with values
    print("\n[+] Uncommon Fields with Values:")
    uncommon_fields_table = PrettyTable()
    uncommon_fields_table.field_names = ["Username", "Field", "Value"]
    uncommon_fields_table.align = "l"
    uncommon_fields_table.max_width = 50
    
    for entry in conn.entries:
        username = entry.sAMAccountName.value if 'sAMAccountName' in entry else "N/A"
        for attr in entry:
            # Skip standard attributes we've already shown
            if attr.key.lower() in [a.lower() for a in standard_attributes]:
                continue
            # Skip empty values
            if not attr.value:
                continue
            # Skip binary data fields
            if isinstance(attr.value, bytes):
                continue
                
            uncommon_fields_table.add_row([username, attr.key, str(attr.value)])
    
    print(uncommon_fields_table)

def enumerate_groups(conn, base_dn):
    print("\n[+] Enumerating groups...")
    group_attributes = ['sAMAccountName', 'name', 'description', 'member']
    
    conn.search(
        search_base=base_dn,
        search_filter='(objectClass=group)',
        search_scope=ldap3.SUBTREE,
        attributes=group_attributes
    )
    
    if not conn.entries:
        print("[-] No groups found")
        return
    
    group_table = PrettyTable()
    group_table.field_names = ["Group Name", "Description", "Members Count"]
    group_table.align = "l"
    
    for entry in conn.entries:
        group_name = entry.sAMAccountName.value if 'sAMAccountName' in entry else entry.name.value
        description = entry.description.value if 'description' in entry else "N/A"
        members = len(entry.member) if 'member' in entry else 0
        
        group_table.add_row([group_name, description, members])
    
    print(group_table)
    
    # Print privileged groups
    privileged_groups = [
        'domain admins', 'enterprise admins', 'schema admins',
        'administrators', 'backup operators', 'account operators',
        'server operators', 'print operators', 'dnsadmins'
    ]
    
    print("\n[+] Privileged Groups Found:")
    for entry in conn.entries:
        group_name = entry.sAMAccountName.value.lower() if 'sAMAccountName' in entry else entry.name.value.lower()
        if any(priv_group in group_name for priv_group in privileged_groups):
            members = entry.member if 'member' in entry else []
            print(f"  - {entry.name.value} ({len(members)} members)")
            if members:
                print("    Members:")
                for member in members:
                    print(f"      {member}")

def enumerate_ous(conn, base_dn):
    print("\n[+] Enumerating Organizational Units (OUs)...")
    ou_attributes = ['name', 'description']
    
    conn.search(
        search_base=base_dn,
        search_filter='(objectClass=organizationalUnit)',
        search_scope=ldap3.SUBTREE,
        attributes=ou_attributes
    )
    
    if not conn.entries:
        print("[-] No OUs found")
        return
    
    ou_table = PrettyTable()
    ou_table.field_names = ["OU Name", "Description"]
    ou_table.align = "l"
    
    for entry in conn.entries:
        name = entry.name.value
        description = entry.description.value if 'description' in entry else "N/A"
        ou_table.add_row([name, description])
    
    print(ou_table)

def check_password_policy(conn, base_dn):
    print("\n[+] Checking password policy...")
    try:
        domain_dn = ','.join([f'dc={part}' for part in base_dn.lower().split(',') if part.startswith('dc=')])
        
        conn.search(
            search_base=f"CN=System,{domain_dn}",
            search_filter='(objectClass=domainDNS)',
            search_scope=ldap3.SUBTREE,
            attributes=['minPwdLength', 'pwdProperties', 'pwdHistoryLength', 'minPwdAge', 'maxPwdAge']
        )
        
        if not conn.entries:
            print("[-] Could not retrieve password policy")
            return
        
        policy = conn.entries[0]
        
        print("  - Minimum password length:", policy.minPwdLength.value if 'minPwdLength' in policy else "N/A")
        
        if 'pwdProperties' in policy:
            props = int(policy.pwdProperties.value)
            print("  - Password complexity:", "Enabled" if props & 1 else "Disabled")
            print("  - Password reversible encryption:", "Enabled" if props & 128 else "Disabled")
        
        print("  - Password history length:", policy.pwdHistoryLength.value if 'pwdHistoryLength' in policy else "N/A")
        
        if 'minPwdAge' in policy:
            min_age = abs(int(policy.minPwdAge.value)) / (10**7 * 60 * 60 * 24)
            print(f"  - Minimum password age: {min_age:.1f} days")
        
        if 'maxPwdAge' in policy:
            max_age = abs(int(policy.maxPwdAge.value)) / (10**7 * 60 * 60 * 24)
            print(f"  - Maximum password age: {max_age:.1f} days")
        
    except LDAPException as e:
        print(f"[-] Error retrieving password policy: {e}")

def check_for_delegation(conn, base_dn):
    print("\n[+] Checking for unconstrained delegation...")
    try:
        conn.search(
            search_base=base_dn,
            search_filter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))',
            search_scope=ldap3.SUBTREE,
            attributes=['sAMAccountName', 'name']
        )
        
        if not conn.entries:
            print("  - No accounts with unconstrained delegation found")
            return
        
        print("  - Accounts with unconstrained delegation:")
        for entry in conn.entries:
            print(f"    - {entry.sAMAccountName.value} ({entry.name.value})")
            
    except LDAPException as e:
        print(f"[-] Error checking for unconstrained delegation: {e}")

def main():
    print_banner()
    args = parse_arguments()
    
    try:
        conn = get_ldap_connection(args)
        base_dn = args.base_dn if args.base_dn else get_base_dn(conn, args.domain)
        
        print(f"\n[+] Base DN: {base_dn}")
        
        # Perform enumeration
        enumerate_users(conn, base_dn)
        enumerate_groups(conn, base_dn)
        enumerate_ous(conn, base_dn)
        check_password_policy(conn, base_dn)
        check_for_delegation(conn, base_dn)
        
        # Display server info
        print("\n[+] LDAP Server Info:")
        print(f"  - Server name: {conn.server.info.other['defaultNamingContext'][0]}")
        print(f"  - Domain controller: {conn.server.info.other['dnsHostName'][0]}")
        print(f"  - Forest name: {conn.server.info.other['rootDomainNamingContext'][0]}")
        
    except LDAPException as e:
        print(f"[-] LDAP error: {e}")
    finally:
        if 'conn' in locals() and conn.bound:
            conn.unbind()

if __name__ == '__main__':
    main()