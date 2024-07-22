import requests
import hashlib
import os
import subprocess
import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_expected_sha256():
    # URL of the text file containing the expected SHA-256 hash value
    hash_url = 'https://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/vlc-3.0.17.4-win64.exe.sha256'
    resp_msg = requests.get(hash_url)
    
    if resp_msg.status_code == requests.codes.ok:
        # Extract and return the expected SHA-256 hash value from the response message body
        hash_lines = resp_msg.text.splitlines()
        for line in hash_lines:
            if 'vlc-3.0.17.4-win64.exe' in line:
                return line.split()[0]  # Extract the hash value
    else:
        raise Exception('Failed to download the expected hash value')

def download_installer():
    # URL of the VLC installer
    installer_url = 'http://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/vlc-3.0.17.4-win64.exe'
    resp_msg = requests.get(installer_url)
    
    if resp_msg.status_code == requests.codes.ok:
        return resp_msg.content
    else:
        raise Exception('Failed to download the VLC installer')

def installer_ok(installer_data, expected_sha256):
    # Calculate the SHA-256 hash value of the downloaded installer
    computed_sha256 = hashlib.sha256(installer_data).hexdigest()
    return computed_sha256 == expected_sha256

def save_installer(installer_data):
    # Save the downloaded installer to the temp directory
    installer_path = os.path.join(os.getenv('TEMP'), 'vlc-3.0.17.4-win64.exe')
    with open(installer_path, 'wb') as file:
        file.write(installer_data)
    return installer_path

def run_installer(installer_path):
    # Run the VLC installer silently
    subprocess.run([installer_path, '/L=1033', '/S'])

def delete_installer(installer_path):
    # Delete the installer file from disk
    os.remove(installer_path)

def main():
    if not is_admin():
        print("This script must be run as an administrator.")
        print("Please right-click on the script and select 'Run as administrator'.")
        return
    
    try:
        # Get the expected SHA-256 hash value of the VLC installer
        expected_sha256 = get_expected_sha256()

        # Download (but don't save) the VLC installer from the VLC website
        installer_data = download_installer()

        # Verify the integrity of the downloaded VLC installer by comparing the expected and computed SHA-256 hash values
        if installer_ok(installer_data, expected_sha256):
            # Save the downloaded VLC installer to disk
            installer_path = save_installer(installer_data)

            # Silently run the VLC installer
            run_installer(installer_path)

            # Delete the VLC installer from disk
            delete_installer(installer_path)
            print("VLC installation completed successfully.")
        else:
            print("Downloaded installer is corrupt. Aborting installation.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    main()
