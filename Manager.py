'''
Minecraft Server Manager is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Minecraft Server Manager is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Minecraft Server Manager.  If not, see {http://www.gnu.org/licenses/}.
'''

import configparser
import json
import base64
import struct
import socket
import threading

class JSONTools:
    @staticmethod
    def read_json(raw_data):
        return json.JSONDecoder().decode(raw_data)

    @staticmethod
    def create_json(json_obj):
        return json.JSONEncoder(indent=2).encode(json_obj)

    @staticmethod
    def serialize_json(json_obj):
        return json.dumps(json_obj)

class FileTools:
    TEXT_ENCODING = "UTF-8"

    # General methods

    @staticmethod
    def write_string(file_path, file_string):
        '''
        Writes file in path 'file_path' with string 'file_string'. Will create directories as necessary
        '''
        with open(file_path, mode="w") as tmp_file_obj:
            tmp_file_obj.write(file_string)

    @staticmethod
    def write_object(file_path, file_object):
        '''
        Writes file in path 'file_path' with file object 'file_object'. Will create directories as necessary
        '''
        with open(file_path, mode="wb") as out_file:
            shutil.copyfileobj(file_object, out_file)
        file_object.close()

    # JSON methods

    @staticmethod
    def read_json(json_path):
        '''
        Returns a JSON object from file path 'json_path'
        '''
        with open(json_path, encoding=FileTools.TEXT_ENCODING) as tmp_file_obj:
            raw_data = tmp_file_obj.read()
        return JSONTools.read_json(raw_data)

    @staticmethod
    def write_json(json_path, json_obj):
        '''
        Writes JSON object 'json_obj' to path 'json_path'
        '''
        with open(json_path, mode="wb") as tmp_file_obj:
            tmp_file_obj.write(JSONTools.create_json(json_obj).encode(FileTools.TEXT_ENCODING))

    # Other methods

    @staticmethod
    def get_file_name(path):
        '''
        Wrapper around os.path.basename
        '''
        return os.path.basename(path)

    @staticmethod
    def exists(file_path):
        '''
        Wrapper around os.path.exists
        '''
        return os.path.exists(file_path)

    @staticmethod
    def is_file(file_path):
        '''
        Wrapper around os.path.isfile
        '''
        return os.path.isfile(file_path)

    def is_dir(dir_path):
        '''
        Wrapper around os.path.isdir
        '''
        return os.path.isdir(dir_path)

    @staticmethod
    def dir_name(file_path):
        '''
        Wrapper around os.path.dirname
        '''
        return os.path.dirname(file_path)

class NetworkManager:
    def __init__(self):
        self.networking_thread = threading.Thread(target=self._listen_loop)
        self.networking_thread.daemon = True

        self.socket = None

    # Varint functions modified for Python 3 from https://gist.github.com/barneygale/1209061
    def _unpack_varint(s):
        d = 0
        for i in range(5):
            b = ord(s.recv(1))
            d |= (b & 0x7F) << 7*i
            if not b & 0x80:
                break
        return d
     
    def _pack_varint(d):
        o = bytes()
        while True:
            b = d & 0x7F
            d >>= 7
            o += struct.pack("B", b | (0x80 if d > 0 else 0))
            if d == 0:
                break
        return o

    def _read_string(self, s):
        str_len = self._unpack_varint(s)
        return s.recv(str_len).decode("UTF-8")

    def _encode_string(self, value):
        '''
        Returns a MC protocol string (varint length followed by UTF-8 encoded string bytes)
        '''
        str_bytes = self._pack_varint(len(value))
        str_bytes += value.encode("UTF-8")
        return str_bytes

    def _setup_socket(self):
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # BIND SOCKET HERE

    def _listen_loop(self):
        pass

class ConfigManager:
    CONFIG_SECT = "ServerManagerConfiguration"
    def __init__(self):
        self.icon_base64 = None

        self.host = None
        self.port = None
        self.motd = None
        self.max_players = None
        self.use_whitelist = None
        self.is_online_mode = None

        self.startup_command = None
        self.version_name = None
        self.protocol_version = None
        self.kick_startup = None
        self.kick_serverold = None
        self.kick_clientold = None
        self.kick_notwhitelisted = None
        self.kick_serveroffline = None

        self.whitelist = None

    # server-icon.png

    def load_icon(self):
        '''
        Returns True if successful, otherwise False
        '''
        if FileTools.exists("server-icon.png"):
            self.icon_base64 = base64.b64encode(open("server-icon.png", "rb").read()).decode("UTF-8")
            return True
        else:
            return False

    def get_base64_icon(self):
        return self.icon_base64

    # server.properties

    def load_server_properties(self):
        '''
        Returns True if successful, otherwise False
        '''
        serverproperties = configparser.ConfigParser()
        try:
            serverproperties.read_string('['+configparser.DEFAULTSECT+']\n'+open("server.properties").read())
        except OSError:
            return False
        self.host = serverproperties[configparser.DEFAULTSECT]['server-ip']
        self.port = serverproperties.getint(configparser.DEFAULTSECT, 'server-port')
        self.motd = serverproperties[configparser.DEFAULTSECT]['motd']
        self.max_players = serverproperties.getint(configparser.DEFAULTSECT, 'max-players')
        self.use_whitelist = serverproperties.getboolean(configparser.DEFAULTSECT, "white-list")
        self.is_online_mode = serverproperties.getboolean(configparser.DEFAULTSECT, "online-mode")

    def get_host(self):
        return self.host

    def get_port(self):
        return self.port

    def get_motd(self):
        return self.motd

    def get_max_players(self):
        return self.max_players

    def get_use_whitelist(self):
        return self.use_whitelist

    def get_is_online_mode(self):
        return self.is_online_mode

    # config.ini

    def load_main_config(self):
        '''
        Returns True if successful, otherwise False
        '''
        config = configparser.ConfigParser()
        config.read("config.ini")
        if len(config.sections()) == 1 and config.sections()[0] == ConfigManager.CONFIG_SECT:
            self.startup_command = config[ConfigManager.CONFIG_SECT]["StartupCommand"]
            self.version_name = config[ConfigManager.CONFIG_SECT]["VersionName"]
            self.protocol_version = config.getint(ConfigManager.CONFIG_SECT, "ProtocolVersion")
            self.kick_startup = config[ConfigManager.CONFIG_SECT]["KickMessage-Startup"]
            self.kick_serverold = config[ConfigManager.CONFIG_SECT]["KickMessage-ServerOlder"]
            self.kick_clientold = config[ConfigManager.CONFIG_SECT]["KickMessage-ClientOlder"]
            self.kick_notwhitelisted = config[ConfigManager.CONFIG_SECT]["KickMessage-NotWhiteListed"]
            self.kick_serveroffline = config[ConfigManager.CONFIG_SECT]["KickMessage-ServerOffline"]
        else:
            return False

    # whitelist.json

    def load_whitelist(self):
        self.whitelist = FileTools.read_json("whitelist.json")

    def in_whitelist(self, uuid):
        for player in self.whitelist:
            if player["uuid"] == uuid:
                return True
        return False

class ProcessManager:
    def set_launch_command(self, command):
        pass

class MainManager:
    def __init__(self):
        pass

class MainGUI:
    pass
