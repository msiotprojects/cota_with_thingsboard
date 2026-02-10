"""
MIT License

Copyright (c) 2024 Hannes Rönn

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import re
import os
import ssl
import gc
import wifi
import time
import hashlib
import binascii
import socketpool
import supervisor
import adafruit_requests
import adafruit_logging as logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

pool = socketpool.SocketPool(wifi.radio)
requests = adafruit_requests.Session(pool, ssl.create_default_context())


class OverTheAirUpdateError(Exception):
    """Base class for all custom exceptions."""


class HashMismatchError(OverTheAirUpdateError):
    """Raised when the hash of a downloaded file does not match the expected value."""
    pass


class InvalidGithubRepoUrlError(OverTheAirUpdateError):
    """Raised when provided GitHub repository URL is invalid."""
    pass


class EmptyGithubRepoError(OverTheAirUpdateError):
    """Raised when attempting to access an empty GitHub repository."""
    pass



######################################################################################################################
#
#    START OF THINGSBOARD
#
class ThingsBoard:
    #FW_TITLE_ATTR = "fw_title"
    #FW_VERSION_ATTR = "fw_version"
    #FW_URL_ATTR = "fw_url"
    #FW_STATE_ATTR = "fw_state"
    #FW_ERROR_ATTR = "fw_error"
    FW_UPDATE_FAILED = "FAILED"
    FW_UPDATE_DOWNLOADING = "DOWNLOADING"
    FW_UPDATE_DOWNLOADED = "DOWNLOADED"
    FW_UPDATE_VERIFIED = "VERIFIED"
    FW_UPDATE_UPDATING = "UPDATING"
    FW_UPDATE_UPDATED = "UPDATED"
    ATTRIBUTE_KEYS = [FW_TITLE_ATTR, FW_VERSION_ATTR, FW_URL_ATTR]

    def __init__(self) -> None:
        self.url = "/No/TB/URL/IS/RELEVANT/ANY/MORE"     # was url param
        self.port = 1234    # arbitrary noise            # was port param
        self.access_token = "NotArealAccessToken"    # was access_token param

        # these are not supposed to be used, but for now we let them get computed
        # in case some code still tries to access them
        self.tb_api_url = f"{self.url}:{self.port}/api/v1/{self.access_token}"
        self.tb_api_attributes_url = f"{self.tb_api_url}/attributes"
        self.tb_api_telemetry_url = f"{self.tb_api_url}/telemetry"
        self.tb_api_attributes_shared_keys_url = self._generate_attribute_url("sharedKeys")
        self.tb_api_attributes_client_keys_url = self._generate_attribute_url("clientKeys")

    def _get_request(self, url: str, headers: dict, retries: int = 3, delay_seconds: int = 5
                     ) -> adafruit_requests.Response:
        for retry in range(1, retries + 1):
            try:
                return requests.get(url, headers=headers)
            except RuntimeError as e:
                if retry < retries:
                    logger.warning(f"{e} - Retrying in {delay_seconds}s ({retry}/{retries})")
                    time.sleep(delay_seconds)
                else:
                    logger.error(f"Failed after {retry} retries. Last error: {e}")
        raise ConnectionError(f"Failed to establish connection to {url} after {retries} retries.")

    def _generate_attribute_url(self, key_type) -> str:    # Not Relevant without Thingsboard
        keys = ','.join(self.ATTRIBUTE_KEYS)
        return f"{self.tb_api_attributes_url}?{key_type}={keys}"

    def _post_request(self, url: str, json: dict, retries: int = 3, delay_seconds: int = 5
                      ) -> adafruit_requests.Response:
        print(json) ; print("Should not have been posted to TB: " + url 
        pass    # RETURNS FROM HERE- CODE BELOW IS IGNORED
        '''
        for retry in range(1, retries + 1):
            try:
                return requests.post(url, json=json)
            except RuntimeError as e:
                if retry < retries:
                    logger.warning(f"{e} - Retrying in {delay_seconds}s ({retry}/{retries})")
                    time.sleep(delay_seconds)
                else:
                    logger.error(f"Failed after {retry} retries. Last error: {e}")
        raise ConnectionError(f"Failed to establish connection to {url} after {retries} retries.")
        '''

    def update_firmware_infos_in_client_attributes(self, firmware_infos: dict) -> None:
        #was self._post_request(self.tb_api_attributes_url, json=firmware_infos)
        
        # need to create file on client containing firmware number (next/.version)
        # from ota_updater.py    def _create_new_version_file(self, latest_version)
        # self._create_new_version_file(latest_version)

    def _get_attributes(self, url: str) -> dict:
        response = self._get_request(url, {})
        response_json = response.json()
        return response_json

    def _get_current_firmware_info_from_client_attributes(self) -> dict:
        json_response = self._get_attributes(self.tb_api_attributes_client_keys_url)
        return json_response.get('client', {})

    def _get_remote_firmware_info_from_shared_attributes(self) -> dict:
        json_response = self._get_attributes(self.tb_api_attributes_shared_keys_url)
        return json_response.get('shared', {})



    def get_firmware_repo_url(self) -> str | None:
        firmware_info = self._get_remote_firmware_info_from_shared_attributes()
        return firmware_info.get(self.FW_URL_ATTR, None)

    def _remote_firmware_exists(self, remote_fw_info: dict) -> bool:
        return all(remote_fw_info.get(attr) is not None for attr in self.ATTRIBUTE_KEYS)

    def _check_firmware_info_differences(self, remote_fw_info: dict, client_fw_info: dict) -> bool:
        """
        Verify whether the firmware information obtained from ThingsBoard's shared and client attributes varies.

        Parameters:
            remote_fw_info (dict): Firmware information retrieved from ThingsBoard shared attributes.
            client_fw_info (dict): Firmware information retrieved from ThingsBoard client attributes.

        Returns:
            bool: True if the firmware information differs, False otherwise.
        """
        client_fw_info[self.FW_VERSION_ATTR] = str(client_fw_info.get(self.FW_VERSION_ATTR, ''))
        return (remote_fw_info.get(self.FW_TITLE_ATTR) != client_fw_info.get(self.FW_TITLE_ATTR) or
                remote_fw_info.get(self.FW_VERSION_ATTR) != client_fw_info.get(self.FW_VERSION_ATTR))

    def send_telemetry(self, data: dict):
        self._post_request(self.tb_api_telemetry_url, json=data)

    def _notify_firmware_update_status(self, firmware_info: dict, fw_status: str):
        title = firmware_info.get(self.FW_TITLE_ATTR)
        version = firmware_info.get(self.FW_VERSION_ATTR)

        download_progress = {f"current_{self.FW_TITLE_ATTR}": title,
                             f"current_{self.FW_VERSION_ATTR}": version,
                             f"{self.FW_STATE_ATTR}": fw_status}
        self.send_telemetry(download_progress)

    def _notify_error(self, error: OverTheAirUpdateError):
        download_progress = {self.FW_STATE_ATTR: self.FW_UPDATE_FAILED,
                             self.FW_ERROR_ATTR: str(error)}
        self.send_telemetry(download_progress)


#
#
#    END OF THINGSBOARD
######################################################################################################################





######################################################################################################################
#
#    GITHUB

class Github:
    def __init__(self, 
                    repo_name:  str, 
                    repo_owner: str, 
                    repo_access_token = None, 
                    repo_branch="main" ):
                    
        self.repo_name = repo_name
        self.repo_owner = repo_owner
        self._github_access_token = repo_access_token
        self.repo_branch = repo_branch
        
        self._github_repo_url_regex_pattern = r'https?://github.com/([^/]+)/([^/]+)(?:/([^/]+))?/?$'
        self._github_api_url = "https://api.github.com/repos/{repo_owner}/{repo_name}/git/trees/{repo_branch}?recursive=1"
        self._github_raw_url = "https://raw.githubusercontent.com/{repo_owner}/{repo_name}/{repo_branch}"
        


    def _extract_github_repo_info_from_url(self, repo_url: str): # for backward compatability
        """
        Extract GitHub repository information from the given URL.

        :param repo_url: The URL of the GitHub repository.
        :type repo_url: str
        :return: A dictionary containing the extracted information: username, repo_name, access_token.
        :rtype: dict
        :raises InvalidGithubRepoUrlError: If the GitHub repository URL is not valid.
        """
        
        username = match.group(1)
        repo_name = match.group(2)
        access_token = match.group(3) if match.group(3) else None
        return {'username': self.repo_owner, 'repo_name': self.repo_name, 'access_token': self._github_access_token}

    def create_sha1_git_hash(self, data: bytes) -> str:
        """
        Generate a SHA1 hash for the given data following `Git's object storage format`_.

        .. _Git's object storage format: https://git-scm.com/book/en/v2/Git-Internals-Git-Objects#_object_storage

        :param data: The data to be hashed.
        :type data: bytes
        :return: The SHA1 hash of the data.
        :rtype: str
        """
        header = f"blob {len(data)}\0"
        store = header.encode() + data
        hash_values_bytes = hashlib.new('sha1', store).digest()
        return binascii.hexlify(hash_values_bytes).decode('utf-8')

    def _get_authentification_header_with_access_token(self) -> dict:
        if self._github_access_token is not None:
            return {"Authorization": f"token {self._github_access_token}"}
        return {}

    def _get_request(self, url: str, headers: dict, retries: int = 3, delay_seconds: int = 5
                     ) -> adafruit_requests.Response:
        for retry in range(1, retries + 1):
            try:
                return requests.get(url, headers=headers)
            except RuntimeError as e:
                if retry < retries:
                    logger.warning(f"{e} - Retrying in {delay_seconds}s ({retry}/{retries})")
                    time.sleep(delay_seconds)
                else:
                    logger.error(f"Failed after {retry} retries. Last error: {e}")
        raise ConnectionError(f"Failed to establish connection to {url} after {retries} retries.")

    def _get_repo_info(self, repo_url: str) -> dict:
        auth_header = self._get_authentification_header_with_access_token()
        response = self._get_request(url=repo_url, headers=auth_header)
        return response.json()

    def _get_repo_tree(self, repo_url: str) -> dict:
        response_json = self._get_repo_info(repo_url)
        return response_json.get("tree", [])

    def _get_file_information_from_repo(self, repo_url: str) -> list[tuple[str, str]]:
        tree = self._get_repo_tree(repo_url)
        files_list = [(item["path"], item["sha"]) for item in tree if item.get("type") == "blob"]
        return files_list

    def _create_github_api_urls(self, repo_info: dict):
        github_raw_url = self._create_github_raw_url(repo_info)
        github_api_url = self._create_github_api_url(repo_info)
        return github_api_url, github_raw_url

    def _download_repo_files(self, repo_file_info: list[tuple[str, str]], github_raw_url: str):
        for git_file_path, git_file_hash in repo_file_info:
            file_url = f"{github_raw_url}/{git_file_path}"
            logger.info(f"Downloading: {file_url}")
            auth_header = self._get_authentification_header_with_access_token()
            git_raw_file_data = self._get_request(url=file_url, headers=auth_header).content
            yield git_file_path, git_raw_file_data, git_file_hash

    def download_files_from_repo(self, github_repo_url: str):
        repo_info = self._extract_github_repo_info_from_url(github_repo_url)
        github_api_url, github_raw_url = self._create_github_api_urls(repo_info)

        repo_file_info = self._get_file_information_from_repo(github_api_url)
        if not repo_file_info:
            raise EmptyGithubRepoError("Repository is empty. Does 'main' branch exist?")
        return self._download_repo_files(repo_file_info, github_raw_url)

    def _get_username_and_repo_name_from_repo_info(self, repo_info: dict):
        return repo_info.get('username'), repo_info.get('repo_name')

    def _create_github_raw_url(self, repo_info: dict) -> str:
        username, repo_name = self._get_username_and_repo_name_from_repo_info(repo_info)
        return self._github_raw_url.format(owner=username, repo_name=repo_name)

    def _create_github_api_url(self, repo_info: dict) -> str:
        username, repo_name = self._get_username_and_repo_name_from_repo_info(repo_info)
        return self._github_api_url.format(owner=username, repo_name=repo_name)


#
#
#    END OF GITHUB
######################################################################################################################



######################################################################################################################
#
#    START OVERTHEAIRUPDATE
#

class OverTheAirUpdate:


    def __init__(self, 
                    repo_name:  str, 
                    repo_owner: str, 
                    repo_access_token = None, 
                    repo_branch="main",

                    secrets_file="settings.toml",
                    
                    module = None,          # OTAupdater subdir in local storage for active firmware
                    app_dir = 'app',        # OTAupdater 'main_dir' where most of app resides like {repo}/app
                    github_src_dir=''       # OTAupdater dir if repo has extra level like {repo}/src/ src/app, src/imgs 
                    new_version_dir='next', # firmware downloads into this dir
                    new_version_file = "VERSION.TXT"    # version number of running code 
                                                        # is stored locally in
                                                        # new_version_dir/new_version_file
                    keep_files = None,        # list of files to never remove
                    keep_folders = None,      # list of folders to never remove (like 'lib')
                    ):
                    
        self.new_version_dir =  new_version_dir  # in ota_updater code
        self.version_filename = new_version_file
            # version number of running code, stored in previous update
            # stored locally in new_version_dir/version_filename
            
        if (keep_files == None)
            keep_files = ["main.py", "boot.py", secrets_file]
        if (keep_folders == None)
            keep_folders = [self.new_version_dir, 'lib']
            

            


        self.github_repo = github_repo.rstrip('/').replace('https://github.com/', '')
        self.github_src_dir = '' if len(github_src_dir) < 1 else github_src_dir.rstrip('/') + '/'
        self.repo_branch = repo_branch
        self.repo_access_token = repo_access_token

        self.app_dir = app_dir
        
        self.module = module.rstrip('/')    # code directory in filesystem, if in subdir
        self.new_version_dir = new_version_dir
        self.secrets_file = secrets_file
        
        self._github = Github(repo_name, repo_owner, repo_access_token)

#####################################################################################
#
# copied from ThingsBoard class
    def is_new_firmware_available(self) -> bool:
        client_fw_info = self._get_current_firmware_info_from_client_attributes()
        remote_fw_info = self._get_remote_firmware_info_from_shared_attributes()
        if self._remote_firmware_exists(remote_fw_info) and self._check_firmware_info_differences(
                remote_fw_info, client_fw_info
        ):
            return True
        return False


    def get_firmware_repo_url(self) -> str | None:
        firmware_info = self._get_remote_firmware_info_from_shared_attributes()
        return firmware_info.get(self.FW_URL_ATTR, None)

    def _remote_firmware_exists(self, remote_fw_info: dict) -> bool:
        return all(remote_fw_info.get(attr) is not None for attr in self.ATTRIBUTE_KEYS)

    def _check_firmware_info_differences(self, remote_fw_info: dict, client_fw_info: dict) -> bool:
        """
        Verify whether the firmware information obtained from ThingsBoard's shared and client attributes varies.

        Parameters:
            remote_fw_info (dict): Firmware information retrieved from ThingsBoard shared attributes.
            client_fw_info (dict): Firmware information retrieved from ThingsBoard client attributes.

        Returns:
            bool: True if the firmware information differs, False otherwise.
        """
        client_fw_info[self.FW_VERSION_ATTR] = str(client_fw_info.get(self.FW_VERSION_ATTR, ''))
        return (remote_fw_info.get(self.FW_TITLE_ATTR) != client_fw_info.get(self.FW_TITLE_ATTR) or
                remote_fw_info.get(self.FW_VERSION_ATTR) != client_fw_info.get(self.FW_VERSION_ATTR))


#
#
#####################################################################################




#####################################################################################
#
#    From rdehuyss/micropython-ota-updater
#

def modulepath(self, path):
        return self.module + '/' + path if self.module else path

def get_version(self, directory, version_file_name='.version'):
    if version_file_name in os.listdir(directory):
        with open(directory + '/' + version_file_name) as f:
            version = f.read()
            return version
    return '0.0'

def get_latest_version(self):
    latest_release = self.http_client.get('https://api.github.com/repos/{}/releases/latest'.format(self.gethub_repo))
    gh_json = latest_release.json()
    try:
         version = gh_json['tag_name']
    except KeyError as e:
        raise ValueError(
            "Release not found: \n",
            "Please ensure release as marked as 'latest', rather than pre-release \n",
            "github api message: \n {} \n ".format(gh_json)
        )
    latest_release.close()
    return version


def _check_for_new_version(self):
    current_version = self.get_version(self.modulepath(self.app_dir))
    latest_version = self.get_latest_version()

    print('Checking version... ')
    print('\tCurrent version: ', current_version)
    print('\tLatest version: ', latest_version)
    return (current_version, latest_version)

        
def install_update_if_available_after_boot(self, ssid, password) -> bool:
        """This method will install the latest version if out-of-date after boot.
        
        This method, which should be called first thing after booting, will check if the 
        next/.version' file exists. 

        - If yes, it initializes the WIFI connection, downloads the latest version and installs it
        - If no, the WIFI connection is not initialized as no new known version is available
        """

    if self.new_version_dir in os.listdir(self.module):
        if '.version' in os.listdir(self.modulepath(self.new_version_dir)):
             latest_version = self.get_version(self.modulepath(self.new_version_dir), '.version')
             print('New update found: ', latest_version)
            OTAUpdater._using_network(ssid, password)
            self.install_update_if_available()
            return True
            
     print('No new updates found...')
     return False

    def install_update_if_available(self) -> bool:
        """This method will immediately install the latest version if out-of-date.
        
        This method expects an active internet connection and allows you to decide yourself
        if you want to install the latest version. It is necessary to run it directly after boot 
        (for memory reasons) and you need to restart the microcontroller if a new version is found.

        Returns
        -------
            bool: true if a new version is available, false otherwise
        """

        (current_version, latest_version) = self._check_for_new_version()
        if latest_version > current_version:
            print('Updating to version {}...'.format(latest_version))
            self._create_new_version_file(latest_version)
            self._download_new_version(latest_version)
            self._copy_secrets_file()
            self._delete_old_version()
            self._install_new_version()
            return True
        
        return False

        @staticmethod
    def _using_network(ssid, password):
        import network
        sta_if = network.WLAN(network.STA_IF)
        if not sta_if.isconnected():
            print('connecting to network...')
            sta_if.active(True)
            sta_if.connect(ssid, password)
            while not sta_if.isconnected():
                pass
        print('network config:', sta_if.ifconfig())


    def _check_for_new_version(self):
        current_version = self.get_version(self.modulepath(self.app_dir))
        latest_version = self.get_latest_version()

        print('Checking version... ')
        print('\tCurrent version: ', current_version)
        print('\tLatest version: ', latest_version)
        return (current_version, latest_version)

    def _create_new_version_file(self, latest_version):
        self.mkdir(self.modulepath(self.new_version_dir))
        with open(self.modulepath(self.new_version_dir + '/.version'), 'w') as versionfile:
            versionfile.write(latest_version)
            versionfile.close()

    def get_version(self, directory, version_file_name='.version'):
        if version_file_name in os.listdir(directory):
            with open(directory + '/' + version_file_name) as f:
                version = f.read()
                return version
        return '0.0'

    def get_latest_version(self):
        latest_release = self.http_client.get('https://api.github.com/repos/{}/releases/latest'.format(self.github_repo))
        gh_json = latest_release.json()
        try:
            version = gh_json['tag_name']
        except KeyError as e:
            raise ValueError(
                "Release not found: \n",
                "Please ensure release as marked as 'latest', rather than pre-release \n",
                "github api message: \n {} \n ".format(gh_json)
            )
        latest_release.close()
        return version



#
#
##################################################################################



def _create_leaf_directories_for_file(self, file_path: str) -> None:
        """
        Create leaf directories for the specified file path if they do not already exist.

        :param file_path: The path to the file.
        :type file_path: str
        """
        parts = file_path.split("/")
        current_path = ""

        for part in parts[:-1]:
            current_path += f"{part}/"
            try:
                os.mkdir(current_path)
            except OSError:
                # Directory already exists
                pass

    def _save_data_to_file(self, data: bytes, filepath: str) -> None:
        with open(filepath, "wb") as file:
            file.write(data)

    def _is_file(self, path: str) -> bool:
        if os.stat(path)[0] & 0o170000 == 0o100000:
            return True
        return False

    def _remove_directory_contents_recursively(
            self, directory: str, keep_files: list[str], keep_folders: list[str]) -> None:
        try:
            for item in os.listdir(directory):
                item_path = f"{directory}/{item}"

                if self._is_file(item_path):
                    if item not in keep_files:
                        os.remove(item_path)
                else:
                    if item not in keep_folders:
                        self._remove_directory_contents_recursively(item_path, keep_files, keep_folders)
                        os.rmdir(item_path)
        except OSError:
            # directory does not exist
            pass

    def _create_folder_if_not_exists(self, folder: str) -> None:
        try:
            os.listdir(folder)
        except OSError:
            os.mkdir(folder)

    def _move_folder_contents(self, source_folder, destination_folder) -> None:
        self._create_folder_if_not_exists(destination_folder)

        for item in os.listdir(source_folder):
            source_item = f"{source_folder}/{item}"
            destination_item = f"{destination_folder}/{item}"

            if self._is_file(source_item):
                with open(source_item, "rb") as src_file:
                    src_file_content = src_file.read()
                    self._save_data_to_file(src_file_content, destination_item)
                os.remove(source_item)
            else:
                self._move_folder_contents(source_item, destination_item)

        os.rmdir(source_folder)

    def _update_firmware(self, directory: str, firmware_info: dict):
        self._remove_directory_contents_recursively(directory, self.keep_files, self.keep_folders)
        self._move_folder_contents(self.new_version_dir, directory)
        self.update_firmware_infos_in_client_attributes(firmware_info)

    def _download_firmware(self, firmware_url: str) -> None:
        """
        Download firmware from the specified URL and perform hash validation.

        Parameters:
            firmware_url (str): The URL to download the firmware from.

        Raises:
            HashMismatchError: If the hash of the downloaded file does not match the expected hash.
        """
        for file_path, raw_file_data, file_hash in self._github.download_files_from_repo(firmware_url):
            created_hash = self._github.create_sha1_git_hash(raw_file_data)

            if created_hash != file_hash:
                raise HashMismatchError(
                    f"Hash value '{created_hash}' does not match the expected hash value '{file_hash}'.")

            destination_path = f"{self.new_version_dir}/{file_path}"
            self._create_leaf_directories_for_file(destination_path)
            logger.info(f"Saving firmware to: {destination_path}")
            self._save_data_to_file(raw_file_data, destination_path)
            gc.collect()

    def download_firmware_files(self, directory: str = ".") -> None:
        """
        Download remote firmware files from a repository to the specified directory.
        Send notifications about the update process to ThingsBoard.

        :param directory: The directory to save the files. Defaults to the current directory.
        :type directory: str
        """
        try:
            firmware_info = self._get_remote_firmware_info_from_shared_attributes()
            logger.info(f"Remote firmware info: {firmware_info}.")

            current_firmware_info = self.()
            logger.info(f"Current firmware info: {current_firmware_info}")

            self._notify_firmware_update_status(current_firmware_info, self.FW_UPDATE_DOWNLOADING)
            firmware_url = firmware_info.get(self.FW_URL_ATTR, '')
            logger.info(f"Downloading firmware from: {firmware_url}.")
            self._download_firmware(firmware_url)
            logger.info(f"Firmware downloaded to: {self.new_version_dir}.")

            for fw_progress in [self.FW_UPDATE_VERIFIED, self.FW_UPDATE_DOWNLOADED, self.FW_UPDATE_UPDATING]:
                self._notify_firmware_update_status(current_firmware_info, fw_progress)

            logger.info(f"Updating firmware to: {firmware_info}.")
            self._update_firmware(directory, firmware_info)
            logger.info("Firmware updated successfully.")

            self._notify_firmware_update_status(current_firmware_info, self.FW_UPDATE_UPDATED)
            logger.info("Initiating device soft reset.")
            supervisor.reload()
        except OverTheAirUpdateError as e:
            logger.error(str(e))
            self._notify_error(e)
            raise
        finally:
            self._remove_directory_contents_recursively(
                self.new_version_dir, keep_files=[], keep_folders=[])


def get_misc_settings() -> dict:
    settings = {
        "wifi_ssid": os.getenv("WIFI_SSID", "Missing_WIFI_SSID"),
        "wifi_password": os.getenv("WIFI_PASSWORD", "Missing_WIFI_PASSWORD"),
        
            # get  GETHUB repo/access from settings.toml
        "repo_name":  os.getenv("GETHUB_REPO_NAME", "Missing_repo_name"),
        "repo_owner": os.getenv("GETHUB_REPO_OWNER", "Missing_repo_owner"),
        "repo_access_token": os.getenv("GETHUB_ACCESS_TOKEN", None)  ,  
        
        "cloud_username":    os.getenv("AIO_USERNAME", None),
        "cloud_access_key":  os.getenv("AIO_KEY", None),
        
        # "thingsboard_url": os.getenv("THINGSBOARD_URL"),
        # "thingsboard_port": os.getenv("THINGSBOARD_PORT"),
        # "thingsboard_device_token": os.getenv("THINGSBOARD_DEVICE_TOKEN")
    }

    return settings
