import subprocess
import sys
import os
import shutil
import getpass
import zipfile

repo_directory = os.path.dirname(os.path.abspath(__file__))

def install_python_venv():
    # Check if python3.12-venv is installed
    try:
        subprocess.run(['apt', 'list', '--installed', 'python3.12-venv'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        # If not installed, install it using apt
        print("python3.12-venv not found. Installing...")
        subprocess.run(['sudo', 'apt', 'install', '-y', 'python3.12-venv'], check=True)

def install_netexec():
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'git+https://github.com/Pennyw0rth/NetExec', '--force', '--break-system-packages'], check=True)

def install_certipy():
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'certipy-ad', '--break-system-packages'], check=True)

# Ensure python3.12-venv is installed
install_python_venv()

try:
    netexec_installed = subprocess.run([sys.executable, '-m', 'pip', 'show', 'NetExec'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if not netexec_installed.stdout:
        install_netexec()
except subprocess.CalledProcessError:
    install_netexec()

try:
    certipy_installed = subprocess.run([sys.executable, '-m', 'pip', 'show', 'certipy-ad'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if not certipy_installed.stdout:
        install_certipy()
except subprocess.CalledProcessError:
    install_certipy()

home_directory = os.path.expanduser("~")
bin_directory = os.path.join(home_directory, ".local", "bin")

if not os.path.exists(bin_directory):
    os.makedirs(bin_directory)

zip_file = os.path.join(repo_directory, "ad-authed.zip")

if os.path.exists(zip_file):
    with zipfile.ZipFile(zip_file, 'r') as zip_ref:
        zip_ref.extractall(bin_directory)

ad_authed_file = os.path.join(repo_directory, "ad-authed.py")
if os.path.exists(ad_authed_file):
    shutil.copy(ad_authed_file, bin_directory)

# Install dependencies and upgrade pyOpenSSL in the pywerview directory
pywerview_directory = os.path.join(bin_directory, "pywerview")

if os.path.exists(pywerview_directory):
    subprocess.run(['pipx', 'install', 'git+https://github.com/Pennyw0rth/NetExec', '--force'], check=True)
    subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pyOpenSSL', '--break-system-packages'], check=True)

current_user = getpass.getuser()
shell = os.environ.get("SHELL", "")
shell_config_file = None

if "bash" in shell:
    shell_type = "bash"
    shell_config_file = os.path.join(home_directory, ".bashrc")
elif "zsh" in shell:
    shell_type = "zsh"
    shell_config_file = os.path.join(home_directory, ".zshrc")

if shell_type in ["bash", "zsh"]:
    path_line = f'export PATH="$PATH:{bin_directory}"\n'
    alias_line = f"alias ad-authed='python3 {bin_directory}/ad-authed.py'\n"
    if shell_config_file:
        with open(shell_config_file, 'a') as config_file:
            config_file.write(path_line)
            config_file.write(alias_line)

for filename in os.listdir(bin_directory):
    file_path = os.path.join(bin_directory, filename)
    if os.path.isfile(file_path):
        subprocess.run(['chmod', '+x', file_path], check=True)

print("Setup complete!")
