# CCDC Environment Deployment with Custom Roles

## Files Included

```
Claude-CCDC-Environment/
├── ludus-range-config-with-roles.yml   # Main Ludus configuration
├── roles/                               # Custom Ansible roles
│   ├── domain_controller/
│   │   ├── tasks/main.yml
│   │   └── defaults/main.yml
│   ├── file_server/
│   │   ├── tasks/main.yml
│   │   └── defaults/main.yml
│   ├── domain_member/
│   │   ├── tasks/main.yml
│   │   └── defaults/main.yml
│   ├── web_server/
│   │   └── tasks/main.yml
│   ├── database_server/
│   │   ├── tasks/main.yml
│   │   └── defaults/main.yml
│   ├── soc_server/
│   │   ├── tasks/main.yml
│   │   └── handlers/main.yml
│   └── kali_setup/
│       └── tasks/main.yml
└── DEPLOY.md                           # This file
```

## Quick Start

### Step 1: Upload Files to Ludus Server

```bash
# On your local machine, create a tarball
tar -czf ccdc-environment.tar.gz ludus-range-config-with-roles.yml roles/

# Copy to Ludus server
scp ccdc-environment.tar.gz user@ludus-server:~/

# SSH into Ludus server
ssh user@ludus-server

# Extract files
cd ~
tar -xzf ccdc-environment.tar.gz
ls -la
# You should see: ludus-range-config-with-roles.yml and roles/
```

### Step 2: Install Custom Roles

Ludus needs to know about your custom roles. There are two ways:

**Option A: Use roles from current directory (Recommended)**

```bash
# Ludus will automatically find roles in ./roles/ when deploying
# Just make sure you're in the directory with the config file
cd ~/Claude-CCDC-Environment
```

**Option B: Install roles globally**

```bash
# Copy roles to Ludus's Ansible roles directory
sudo cp -r roles/* /opt/ludus/ansible/roles/

# Or if using local user Ansible
mkdir -p ~/.ansible/roles
cp -r roles/* ~/.ansible/roles/
```

### Step 3: Set the Range Configuration

```bash
# From the directory containing your config and roles folder
cd ~/Claude-CCDC-Environment

# Set the configuration
ludus range config set -f ludus-range-config-with-roles.yml
```

**Expected Output:**
```
Successfully set range configuration
```

### Step 4: Deploy the Range

```bash
ludus range deploy
```

**This will take 45-60 minutes ⏱️**

### Step 5: Monitor Progress

```bash
# Check status
ludus range status

# Watch logs
ludus range logs --follow

# List VMs
ludus range list
```

## What Gets Deployed

### Windows Systems (VLAN 10)

| VM | IP | Role | Description |
|----|----|----|-------------|
| dc-01 | 10.10.10.10 | Domain Controller | AD DC for blue.lab, DNS, 7 users |
| fs-01 | 10.10.10.20 | File Server | 3 SMB shares, domain-joined |
| ws-01 | 10.10.10.101 | Workstation | Domain-joined Windows 10 |
| ws-02 | 10.10.10.102 | Workstation | Domain-joined Windows 10 |

### Linux Systems (VLAN 10)

| VM | IP | Role | Description |
|----|----|----|-------------|
| web-01 | 10.10.10.30 | Web Server | Apache + PHP |
| db-01 | 10.10.10.40 | Database | MySQL with ccdc_app database |
| soc-01 | 10.10.10.50 | SOC/Monitoring | rsyslog, fail2ban, monitoring tools |

### Attacker (VLAN 99)

| VM | IP | Role | Description |
|----|----|----|-------------|
| kali-01 | 10.99.99.10 | Attacker | Kali with pentesting tools |

## Domain Users

**Domain:** blue.lab

| Username | Password | Groups |
|----------|----------|--------|
| DomainAdmin | P@ssw0rd123! | Domain Admins, Enterprise Admins |
| jsmith | Summer2024! | Domain Users |
| mjones | Winter2024! | Domain Users |
| bwilliams | Spring2024! | Domain Users |
| tdavis | Fall2024! | Domain Users |
| kbrown | Autumn2024! | Domain Users |
| lmiller | Seasons2024! | Domain Users |

## Post-Deployment Verification

### 1. Check All VMs Are Running

```bash
ludus range list
```

All 8 VMs should show "running" status.

### 2. Test Domain Controller

```bash
# RDP to DC01
ludus range rdp dc-01

# Or SSH if configured
ludus range ssh dc-01
```

**On DC01, verify:**
```powershell
# Check AD services
Get-Service ADWS,DNS,Netlogon

# List domain users
Get-ADUser -Filter *

# Verify domain
Get-ADDomain
```

You should see 7 user accounts.

### 3. Test File Server

```bash
# Connect to FS01
ludus range rdp fs-01
```

**On FS01:**
```powershell
# Check domain membership
Get-ComputerInfo | Select CsDomain

# List shares
Get-SmbShare
```

You should see 3 shares: CompanyData, IT, HR

### 4. Test Web Server

```bash
# SSH to web server
ssh ludus@10.10.10.30

# Check Apache
sudo systemctl status apache2

# Test web page
curl http://localhost
```

**From another system:**
```bash
curl http://10.10.10.30
```

### 5. Test Database

```bash
# SSH to database server
ssh ludus@10.10.10.40

# Login to MySQL
mysql -u root -p'MySQLR00t!'

# Check database
SHOW DATABASES;
```

You should see `ccdc_app` database.

### 6. Test SOC Server

```bash
# SSH to SOC server
ssh ludus@10.10.10.50

# Check rsyslog
sudo systemctl status rsyslog

# Check log directory
ls -la /var/log/remote/
```

### 7. Test Kali

```bash
# SSH to Kali
ssh ludus@10.99.99.10

# Check tools
which nmap metasploit bloodhound

# Check repositories
ls -la /opt/tools/
```

## Troubleshooting

### Config Set Fails

**Error:** "Additional property tasks is not allowed"
- **Solution:** Make sure you're using `ludus-range-config-with-roles.yml`, NOT the old config with inline tasks

**Error:** "Role not found"
- **Solution:** Ensure `roles/` directory is in the same directory as the config file

```bash
# Check structure
ls -la
# Should see:
# ludus-range-config-with-roles.yml
# roles/

# Verify roles exist
ls -la roles/
```

### Deploy Fails

**Check logs:**
```bash
ludus range logs
ludus range logs --vm dc-01  # Check specific VM
```

**Common issues:**

1. **DC promotion fails**
   - Check network connectivity
   - Verify DNS settings
   - Review: `ludus range logs --vm dc-01`

2. **Domain join fails**
   - Ensure DC is fully promoted first
   - Check DNS (should be 10.10.10.10)
   - Verify credentials

3. **Ansible role errors**
   - Check role syntax: `ansible-playbook --syntax-check`
   - Verify roles directory structure

### Start Over

```bash
# Destroy everything
ludus range destroy

# Redeploy
cd ~/Claude-CCDC-Environment
ludus range config set -f ludus-range-config-with-roles.yml
ludus range deploy
```

## Customizing the Environment

### Modify Domain Users

Edit `roles/domain_controller/defaults/main.yml`:

```yaml
domain_users:
  - name: "newuser"
    firstname: "New"
    surname: "User"
    password: "Password123!"
    groups: ["Domain Users"]
```

Then redeploy:
```bash
ludus range deploy
```

### Add More Shares

Edit `roles/file_server/tasks/main.yml`, add to the shares loop:

```yaml
- { name: "Finance", path: "C:\\Shares\\Finance", description: "Finance files" }
```

### Change Passwords

Edit the `defaults/main.yml` files in respective roles:
- `domain_controller/defaults/main.yml` - Domain passwords
- `database_server/defaults/main.yml` - MySQL password

### Add Vulnerabilities

**Example: Weak SMB share in file_server role**

Edit `roles/file_server/tasks/main.yml`, add:

```yaml
- name: Create insecure public share (TRAINING ONLY)
  win_share:
    name: "Public"
    path: "C:\\Shares\\Public"
    full: "Everyone"
    state: present
```

## Resource Requirements

**Minimum:**
- CPU: 17 cores
- RAM: 30GB
- Storage: 300GB

**Recommended:**
- CPU: 20+ cores
- RAM: 40GB
- Storage: 500GB SSD

## Network Information

**VLAN 10 (Corporate):** 10.10.10.0/24
- Gateway: 10.10.10.1
- DNS: 10.10.10.10 (DC01)

**VLAN 99 (Attacker):** 10.99.99.0/24
- Isolated from corporate network

## Training Scenarios

Once deployed, you can practice:

**Blue Team:**
- Baseline the environment
- Implement monitoring
- Harden systems
- Incident response

**Red Team:**
- Network reconnaissance
- Password spraying
- Lateral movement
- Privilege escalation

**Purple Team:**
- Combined attack & detection
- Threat hunting
- Improving defenses

## Support

**Check documentation:**
- Ludus: https://docs.ludus.cloud/
- This README
- Role-specific documentation in `roles/*/tasks/main.yml`

**Get help:**
- Review logs: `ludus range logs`
- Ludus community forums
- CCDC preparation resources

---

**Happy Training! 🎯🛡️**
