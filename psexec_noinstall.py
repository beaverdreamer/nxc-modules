import json
import errno
from os.path import abspath, join, split, exists, splitext, getsize, sep
from os import makedirs, remove, stat
import time
from nxc.paths import TMP_PATH
from nxc.protocols.smb.remotefile import RemoteFile
from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SessionError

CHUNK_SIZE = 4096

def get_list_from_option(opt):
    """Takes a comma-separated string and converts it to a list of lowercase strings.
    It filters out empty strings from the input before converting.
    """
    return [o.lower() for o in filter(bool, opt.split(","))]

class PSExecNoInstall:
    def __init__(
            self,
            smb,
            logger,
    ):
        self.smb = smb
        self.host = self.smb.conn.getRemoteHost()
        self.logger = logger

    def list_path(self, share, subfolder):
        """Returns a list of paths for a given share/folder."""
        filelist = []
        try:
            # Get file list for the current folder
            filelist = self.smb.conn.listPath(share, subfolder + "*")

        except SessionError as e:
            self.logger.debug(f'Failed listing files on share "{share}" in folder "{subfolder}".')
            self.logger.debug(str(e))

            if "STATUS_ACCESS_DENIED" in str(e):
                self.logger.debug(f'Cannot list files in folder "{subfolder}".')

            elif "STATUS_OBJECT_PATH_NOT_FOUND" in str(e):
                self.logger.debug(f"The folder {subfolder} does not exist.")

        return filelist

    def get_remote_file(self, share, path):
        """Checks if a path is readable in a SMB share."""
        try:
            return RemoteFile(self.smb.conn, path, share, access=FILE_READ_DATA)
        except SessionError:
            self.logger.fail("Got a session error while connecting to IPC$.")

    def connect_to_share(self):
        try:
            self.find_pipe("IPC$", "")
        except SessionError as e:
            self.logger.exception(e)
            self.logger.fail("Got a session error while connecting to IPC$.")

    def find_pipe(self, share_name, folder):
        filelist = self.list_path(share_name, folder + "*")
        pipe_name = "RemCom_communicaton"
        for file in filelist:
            if file.get_longname().lower() == "RemCom_communicaton".lower():
                self.logger.success(f'PIPE {pipe_name} readable and found in IPC$')  # debug

class NXCModule:
    """psexec_noinstall module
    Module by @beaverdreamer and inpired by https://github.com/MzHmO/psexec_noinstall
    Based on SpiderPlus module by @vincd
    """

    name = "psexec_noinstall"
    description = "Searches for open RemCom_communication pipe, which means we can use it to get RCE via low priveleged user."
    supported_protocols = ["smb"]
    opsec_safe = True  # Does the module touch disk?
    multiple_hosts = True  # Does the module support multiple hosts?

    def options(self, context, module_options):
        pass

    def on_login(self, context, connection):

        search = PSExecNoInstall(
            connection,
            context.log
        )

        search.connect_to_share()
