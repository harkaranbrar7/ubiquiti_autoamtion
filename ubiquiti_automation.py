import logging
import os
import re
import paramiko
from paramiko.auth_handler import AuthenticationException, SSHException
from scp import SCPClient, SCPException

logging.basicConfig(level=logging.INFO)
logging.getLogger("paramiko.transport").disabled = True
logger = logging.getLogger("Ubiquiti-Automation")

class Ubiquiti_Automation():
    """Client to interact with a remote host via SSH & SCP."""

    ...

    def __init__(self, ip_address: str, radio_username: str,
                 radio_password: str) -> None:

        self.ip_address = ip_address
        self.radio_username = radio_username
        self.radio_password = radio_password
        self.client = None
        self.scp = None
        self.remote_path = "/var/tmp/"
        self.local_path = None

    def _connect(self):
        """Open connection to remote host. """
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                self.ip_address,
                username=self.radio_username,
                password=self.radio_password,
                timeout=5,
                look_for_keys=False,
                banner_timeout=200,
                auth_timeout=10,
            )
            self.scp = SCPClient(self.client.get_transport())
        except AuthenticationException as error:
            logger.error(
                f'Authentication failed: did you remember your password? {error}'
            )
            raise error
        return self.client

    def disconnect(self):
        """Close ssh connection."""
        if self.client:
            self.client.close()
        if self.scp:
            self.scp.close()

    def _upload_single_file(self, file):
        """Upload a single file to a remote directory."""
        upload = None
        try:
            self.scp.put(file, recursive=True, remote_path=self.remote_path)
            upload = file
        except SCPException as error:
            logger.error(error)
            raise error
        # finally:
        logger.info(f'Uploaded {file} to {self.remote_path}')
        return upload

    def download_file(self, remote_path, local_path):
        """Download file from remote host."""
        download = None
        try:
            self.conn = self._connect()
            self.scp.get(remote_path=remote_path, local_path=local_path)
            download = local_path
        except SCPException as error:
            logger.error(error)
            raise error
        # finally:
        logger.info(f'Downloaded {remote_path} to {local_path}')
        return download

    def execute_commands(self, commands):
        """
        Execute multiple commands in succession.

        :param commands: List of unix commands as strings.
        :type commands: List[str]
        """
        self.conn = self._connect()
        for cmd in commands:
            stdin, stdout, stderr = self.client.exec_command(cmd)
            stdout.channel.recv_exit_status()
            response = stdout.readlines()
            for line in response:
                logger.info(f'INPUT: {cmd} | OUTPUT: {line}')
            return response

    def __get_hashed_password(self):
        """
        Helper function to get hash of new password from radio.
        """
        response = self.execute_commands(commands=["cat /etc/passwd"])
        value = response[0]
        pattern = "(?<=\:)(.*?)(?=\:)"
        password_hash = re.search(pattern, value)
        return str(password_hash[0])

    def __modify_config(self):
        """
        edit the configuration file to add a new password to config file in local machine.
        """

        file_to_dict = {
            line.split("=")[0]: line.split("=")[1]
            for line in open(os.path.join(self.local_path, "system.cfg"))
        }
        file_to_dict['users.1.password'] = self.__get_hashed_password() + "\n"

        with open(os.path.join(self.local_path, "system.cfg"), 'w') as file:
            for key, value in file_to_dict.items():
                file.write('%s=%s' % (key, value))
        return os.path.join(self.local_path, "system.cfg")

    def change_password(self, new_password: str):
        try:
            self.conn = self._connect()

            # Change password for the radio
            stdin, stdout, stderr = self.client.exec_command("passwd")
            stdin.write(f'{new_password}' '\n' f'{new_password}' '\n')
            stdin.close()
            logger.info("Password is changed is initiated")
            self.local_path = f"radio_cfgs/{self.ip_address}"
            if not os.path.exists(self.local_path):
                os.makedirs(self.local_path)

            self.download_file(remote_path="/var/tmp/system.cfg",
                               local_path=self.local_path)

            modified_file = self.__modify_config()
            self._upload_single_file(file=modified_file)

            # # Apply new config via two ways. either one of the commands will work
            command = ["/usr/etc/rc.d/rc.softrestart save"]
            # # command = "cfgmtd -f /tmp/system.cfg -w"
            self.execute_commands(commands=command)

            logger.info(f"Password is changed on {self.ip_address}")
            return f"Password is changed on {self.ip_address}"
        except Exception as e:
            logger.error(f"Exception:{e}:{self.ip_address}")

            
if __name__ == "__main__":
    # give you details here for the radio.
    script = Ubiquiti_Automation(ip_address="192.168.1.20",
                                 radio_username='ubnt',
                                 radio_password="ubnt")
    print(script.change_password(new_password="new_password"))  
            
  
