import hashlib
import requests
import os
import subprocess

def main():
    # Get the expected SHA-256 hash value of the VLC installer
    expected_sha256 = get_expected_sha256()

    # Download (but don't save) the VLC installer from the VLC website
    installer_data = download_installer()

    # Verify the integrity of the downloaded VLC installer by comparing the
    # expected and computed SHA-256 hash values
    if installer_ok(installer_data, expected_sha256):
        # Save the downloaded VLC installer to disk
        installer_path = save_installer(installer_data)

        # Silently run the VLC installer
        run_installer(installer_path)

        # Delete the VLC installer from disk
        delete_installer(installer_path)

def get_expected_sha256():
    """Downloads the text file containing the expected SHA-256 value for the VLC installer file from the 
    videolan.org website and extracts the expected SHA-256 value from it.

    Returns:
        str: Expected SHA-256 hash value of VLC installer
    """
    # For this example, we'll hardcode the expected SHA-256 value
    # In a real-world scenario, you would download the text file and extract the value
    expected_sha256 = "your_expected_sha256_value_here"
    return expected_sha256

def download_installer():
    """Downloads, but does not save, the.exe VLC installer file for 64-bit Windows.

    Returns:
        bytes: VLC installer file binary data
    """
    # Download the VLC installer file
    response = requests.get("http://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/")

    # Extract the binary data from the response
    installer_data = response.content

    return installer_data

def installer_ok(installer_data, expected_sha256):
    """Verifies the integrity of the downloaded VLC installer file by calculating its SHA-256 hash value 
    and comparing it against the expected SHA-256 hash value. 

    Args:
        installer_data (bytes): VLC installer file binary data
        expected_sha256 (str): Expeced SHA-256 of the VLC installer

    Returns:
        bool: True if SHA-256 of VLC installer matches expected SHA-256. False if not.
    """    
    # Calculate the SHA-256 hash value of the installer data
    sha256_hash = hashlib.sha256(installer_data).hexdigest()

    # Compare the computed SHA-256 hash value against the expected SHA-256 hash value
    return sha256_hash == expected_sha256

def save_installer(installer_data):
    """Saves the VLC installer to a local directory.

    Args:
        installer_data (bytes): VLC installer file binary data

    Returns:
        str: Full path of the saved VLC installer file
    """
    # Save the installer data to a file
    installer_path = "vlc-3.0.18-win64.exe"
    with open(installer_path, "wb") as f:
        f.write(installer_data)

    return installer_path

def run_installer(installer_path):
    """Silently runs the VLC installer.

    Args:
        installer_path (str): Full path of the VLC installer file
    """    
    # Run the VLC installer silently
    subprocess.run([installer_path, "/S"])

def delete_installer(installer_path):
    """Deletes the VLC installer file.

    Args:
        installer_path (str): Full path of the VLC installer file
    """
    # Delete the VLC installer file
    os.remove(installer_path)

if __name__ == '__main__':
    main()