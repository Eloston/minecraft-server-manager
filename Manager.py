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
import io
import enum
import logging
import os
import os.path
import sys
import urllib.request
import shutil

from PySide import QtGui

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
        with open(json_path, encoding=TEXT_ENCODING) as tmp_file_obj:
            raw_data = tmp_file_obj.read()
        return JSONTools.read_json(raw_data)

    @staticmethod
    def write_json(json_path, json_obj):
        '''
        Writes JSON object 'json_obj' to path 'json_path'
        '''
        with open(json_path, mode="wb") as tmp_file_obj:
            tmp_file_obj.write(JSONTools.create_json(json_obj).encode(TEXT_ENCODING))

class HandshakeState(enum.Enum):
    error = -1
    status = 1
    login = 2

class NetworkManagerClass:
    def __init__(self):
        self.networking_thread = threading.Thread(target=self._listen_loop)
        self.networking_thread.daemon = True

        self.client_socket = None
        self.server_socket = None

    def _get_player_uuid(self, playername):
        headers = dict()
        headers["Content-Type"] = "application/json"
        headers["User-Agent"] = "MSM"
        data = JSONTools.serialize_json([playername]).encode(TEXT_ENCODING)
        try:
            server_response = JSONTools.read_json(urllib.request.urlopen(urllib.request.Request("https://api.mojang.com/profiles/minecraft", data, headers)).read().decode(TEXT_ENCODING))
            if len(server_response) > 0:
                if server_response[0]["name"] == playername:
                    return server_response[0]["id"]
                else:
                    LOG.error("Mojang server responded with an incorrect username")
                    return None
            else:
                LOG.warning("Player does not exist according to Mojang")
                return None
        except:
            LOG.exception("Error while trying to get player UUID")
            LOG.error("Unable to get player UUID")
            return None

    # Varint functions modified for Python 3 from https://gist.github.com/barneygale/1209061
    def _unpack_varint_socket(self, s):
        d = 0
        for i in range(5):
            b = ord(s.recv(1))
            d |= (b & 0x7F) << 7*i
            if not b & 0x80:
                break
        return d

    def _unpack_varint(self, bytesio):
        d = 0
        for i in range(5):
            b = ord(bytesio.read(1))
            d |= (b & 0x7F) << 7*i
            if not b & 0x80:
                break
        return d
     
    def _pack_varint(self, d):
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
        return s.read(str_len).decode("UTF-8")

    def _encode_string(self, value):
        '''
        Returns a MC protocol string (varint length followed by UTF-8 encoded string bytes)
        '''
        str_bytes = self._pack_varint(len(value))
        str_bytes += value.encode("UTF-8")
        return str_bytes

    def _read_ushort(self, s):
        fmt = ">H"
        return struct.unpack(fmt, s.read(struct.calcsize(fmt)))[0]

    def _read_packet(self):
        packet_len = self._unpack_varint_socket(self.client_socket)
        packet_buffer = io.BytesIO(self.client_socket.recv(packet_len))
        packet_id = self._unpack_varint(packet_buffer)
        return packet_id, packet_buffer

    def _send_packet(self, data):
        data.seek(0)
        raw_bytes = data.read()
        self.client_socket.send(self._pack_varint(len(raw_bytes)))
        self.client_socket.send(raw_bytes)

    def _read_handshake(self):
        packet_id, packet_buffer = self._read_packet()
        if not packet_id == 0x00:
            LOG.error("Packet ID is not a Handshake")
            return HandshakeState.error
        protocol_ver = self._unpack_varint(packet_buffer)
        if protocol_ver > ConfigManager.get_protocol_version():
            LOG.warning("Server is older than client.")
            LOG.warning("Client: " + str(protocol_ver) + ", Server: " + str(ConfigManager.get_protocol_version()))
            self._send_disconnect(ConfigManager.get_kick_serverold())
            return HandshakeState.error
        elif protocol_ver < ConfigManager.get_protocol_version():
            LOG.warning("Client is older than server.")
            LOG.warning("Client: " + str(protocol_ver) + ", Server: " + str(ConfigManager.get_protocol_version()))
            self._send_disconnect(ConfigManager.get_kick_clientold())
            return HandshakeState.error
        self._read_string(packet_buffer) # Address client uses to connect
        self._read_ushort(packet_buffer) # Port client uses to connect
        next_state = self._unpack_varint(packet_buffer)
        if next_state == HandshakeState.status.value:
            LOG.info("Client requested status")
            return HandshakeState.status
        elif next_state == HandshakeState.login.value:
            LOG.info("Client trying to login")
            return HandshakeState.login
        else:
            LOG.error("Invalid status in Handshake")
            return HandshakeState.error

    def _read_status_request(self):
        packet_id, packet_buffer = self._read_packet() # Packet contains no fields
        if packet_id == 0x00:
            return True
        else:
            LOG.error("Client status request is malformed")
            LOG.debug("Got packet " + hex(packet_id))
            return False

    def _send_status_response(self):
        packet_buffer = io.BytesIO()
        packet_buffer.write(self._pack_varint(0x00))
        response_dict = dict()
        response_dict["version"] = dict()
        response_dict["version"]["name"] = ConfigManager.get_version_name()
        response_dict["version"]["protocol"] = ConfigManager.get_protocol_version()
        response_dict["players"] = dict()
        response_dict["players"]["max"] = ConfigManager.get_max_players()
        response_dict["players"]["online"] = 0
        response_dict["description"] = dict()
        response_dict["description"]["text"] = ConfigManager.get_motd()
        base64ed_icon = ConfigManager.get_base64_icon()
        if not base64ed_icon is None:
            response_dict["favicon"] = "data:image/png;base64," + base64ed_icon
        packet_buffer.write(self._encode_string(JSONTools.serialize_json(response_dict)))
        self._send_packet(packet_buffer)

    def _read_ping(self):
        packet_id, packet_buffer = self._read_packet()
        if packet_id == 0x01:
            LOG.info("Got ping packet")
            self._send_packet(packet_buffer)
        else:
            LOG.warning("Did not receive ping packet")
            LOG.debug("Got packet " + hex(packet_id))

    def _read_login_start(self):
        packet_id, packet_buffer = self._read_packet()
        if packet_id == 0x00:
            return self._read_string(packet_buffer)
        else:
            LOG.error("Did not receive Login Start packet")
            LOG.debug("Got packet " + hex(packet_id))
            return None

    def _send_disconnect(self, reason):
        # NOTE: This is a Login 0x00 Disconnect packet. This is not to be confused with Play 0x40 Disconnect packet of the same format.
        packet_buffer = io.BytesIO()
        packet_buffer.write(self._pack_varint(0x00))
        disconnect_dict = dict()
        disconnect_dict["text"] = reason
        packet_buffer.write(self._encode_string(JSONTools.serialize_json(disconnect_dict)))
        self._send_packet(packet_buffer)

    def _setup_server_socket(self):
        self.server_socket = socket.socket()
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((ConfigManager.get_host(), ConfigManager.get_port()))

    def _configure_client_socket(self):
        self.client_socket.setblocking(True)
        self.client_socket.settimeout(5.0)

    def _stop_client_socket(self):
        self.client_socket.shutdown(socket.SHUT_RDWR)
        self.client_socket.close()

    def _listen_loop(self):
        try:
            self._setup_server_socket()
            while not STATE.pending_shutdown:
                LOG.info("Listening for clients")
                self.server_socket.listen(5)
                self.client_socket, address = self.server_socket.accept()
                if STATE.pending_forcestartup:
                    LOG.info("Forcing server startup now")
                    self.client_socket.close()
                    self.server_socket.close()
                    ProcessManager.launch_server()
                    self._setup_server_socket()
                    STATE.set_pending_forcestartup(False)
                    continue
                LOG.info("Got connection from " + address[0] + ", port " + str(address[1]))
                self._configure_client_socket()
                try:
                    shake_state = self._read_handshake()
                    if shake_state == HandshakeState.status:
                        if self._read_status_request():
                            self._send_status_response()
                            self._read_ping()

                    elif shake_state == HandshakeState.login:
                        username = self._read_login_start()
                        if STATE.temp_offline:
                            self._send_disconnect(ConfigManager.get_kick_serveroffline())
                            self._stop_client_socket()
                            LOG.info("Client disconnected due to server offline")
                            continue
                        if not username is None:
                            LOG.info("Player username: " + username)
                            if ConfigManager.get_is_online_mode():
                                player_uuid = self._get_player_uuid(username)
                                if player_uuid is None:
                                    self._send_disconnect(ConfigManager.get_kick_authenticationerror())
                                else:
                                    LOG.info("Player UUID: " + player_uuid)
                                    if ConfigManager.uuid_in_whitelist(player_uuid):
                                        self._send_disconnect(ConfigManager.get_kick_startup())
                                        self._stop_client_socket()
                                        self.server_socket.close()
                                        ProcessManager.launch_server()
                                        self._setup_server_socket()
                                        continue
                                    else:
                                        self._send_disconnect(ConfigManager.get_kick_notwhitelisted())
                                        LOG.info("Player is not whitelisted")
                            else:
                                if ConfigManager.name_in_whitelist(username):
                                    self._send_disconnect(ConfigManager.get_kick_startup())
                                    self._stop_client_socket()
                                    self.server_socket.close()
                                    ProcessManager.launch_server()
                                    self._setup_server_socket()
                                    continue
                                else:
                                    self._send_disconnect(ConfigManager.get_kick_notwhitelisted())
                                    LOG.info("Player is not whitelisted")

                    else:
                        LOG.error("Internal application error occured")
                        LOG.debug("Invalid state " + str(shake_state))

                except socket.timeout:
                    LOG.exception("Timeout exception details")
                    LOG.error("Client connection timed-out")
                except:
                    LOG.exception("Exception thrown during client communication")
                    LOG.error("An error occured during client communication")
                self._stop_client_socket()
            Interface.close()
        except:
            LOG.exception("Unexpected exception thrown in listen thread")

    def start(self):
        self.networking_thread.start()

class ConfigManagerClass:
    CONFIG_SECT = "ServerManagerConfiguration"
    def __init__(self):
        self.icon_base64 = None

        self.host = None
        self.port = None
        self.motd = None
        self.max_players = None
        self.use_whitelist = None
        self.is_online_mode = None

        self.version_name = None
        self.protocol_version = None
        self.kick_startup = None
        self.kick_serverold = None
        self.kick_clientold = None
        self.kick_notwhitelisted = None
        self.kick_authenticationerror = None
        self.kick_serveroffline = None

        self.whitelist = None

    def load_configuration(self):
        if self.load_server_properties():
            if self.get_use_whitelist():
                self.load_whitelist()
            if self.load_main_config():
                self.load_icon()
                return True
        return False

    # server-icon.png

    def load_icon(self):
        '''
        Returns True if successful, otherwise False
        '''
        if os.path.exists("server-icon.png"):
            self.icon_base64 = base64.b64encode(open("server-icon.png", "rb").read()).decode("UTF-8")
            LOG.info("successfully loaded server icon")
        else:
            LOG.info("Could not find a server icon 'server-icon.png'")

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
        return True

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
            logging_level = config[ConfigManager.CONFIG_SECT]["LoggingLevel"]
            logging_format = config.get(ConfigManager.CONFIG_SECT, "LoggingFormat", raw=True)
            logging_filename = config.get(ConfigManager.CONFIG_SECT, "LoggingFile", raw=True)
            formatter = logging.Formatter(logging_format)
            stream_handler = logging.StreamHandler(sys.stdout)
            stream_handler.setFormatter(formatter)
            file_handler = logging.FileHandler(logging_filename, mode="w")
            file_handler.setFormatter(formatter)
            LOG.setLevel(logging_level)
            LOG.handlers = list()
            LOG.addHandler(stream_handler)
            LOG.addHandler(file_handler)
            LOG.info("***LOGGING START***")
            LOG.debug("server-ip: " + self.host)
            LOG.debug("server-port: " + str(self.port))
            LOG.debug("motd: " + self.motd)
            LOG.debug("max-players: " + str(self.max_players))
            LOG.debug("Using whitelist: " + str(self.use_whitelist))
            LOG.debug("Is online mode: " + str(self.is_online_mode))

            startup_command = config.get(ConfigManager.CONFIG_SECT, "StartupCommand", raw=True)
            ProcessManager.set_launch_command(startup_command)

            self.version_name = config[ConfigManager.CONFIG_SECT]["VersionName"]
            self.protocol_version = config.getint(ConfigManager.CONFIG_SECT, "ProtocolVersion")
            self.kick_startup = config[ConfigManager.CONFIG_SECT]["KickMessage-Startup"]
            self.kick_serverold = config[ConfigManager.CONFIG_SECT]["KickMessage-ServerOlder"]
            self.kick_clientold = config[ConfigManager.CONFIG_SECT]["KickMessage-ClientOlder"]
            self.kick_notwhitelisted = config[ConfigManager.CONFIG_SECT]["KickMessage-NotWhiteListed"]
            self.kick_authenticationerror = config[ConfigManager.CONFIG_SECT]["KickMessage-AuthenticationError"]
            self.kick_serveroffline = config[ConfigManager.CONFIG_SECT]["KickMessage-ServerOffline"]
            return True
        else:
            return False

    def get_version_name(self):
        return self.version_name

    def get_protocol_version(self):
        return self.protocol_version

    def get_kick_startup(self):
        return self.kick_startup

    def get_kick_serverold(self):
        return self.kick_serverold

    def get_kick_clientold(self):
        return self.kick_clientold

    def get_kick_notwhitelisted(self):
        return self.kick_notwhitelisted

    def get_kick_authenticationerror(self):
        return self.kick_authenticationerror

    def get_kick_serveroffline(self):
        return self.kick_serveroffline

    def set_kick_serveroffline(self, new_msg):
        self.kick_serveroffline = new_msg

    # whitelist.json

    def load_whitelist(self):
        self.whitelist = FileTools.read_json("whitelist.json")

    def uuid_in_whitelist(self, uuid):
        uuid = uuid.replace("-", "")
        for player in self.whitelist:
            if player["uuid"].replace("-", "") == uuid:
                return True
        return False

    def name_in_whitelist(self, name):
        for player in self.whitelist:
            if player["name"] == name:
                return True
        return False

class ProcessManagerClass:
    JAVA_PATH_KEY = "${JAVA_PATH}"
    def __init__(self):
        self.launch_command = None
        self.server_running = False

    def _get_java_path(self):
        if sys.platform == "win32" or sys.platform == "cygwin":
            import winreg
            try:
                JAVA_REGISTRY_PATH = "Software\\JavaSoft\\Java Runtime Environment"
                current_java_version = winreg.QueryValueEx(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, JAVA_REGISTRY_PATH, access=winreg.KEY_READ | winreg.KEY_WOW64_64KEY), "CurrentVersion")[0]
                java_binary_path = winreg.QueryValueEx(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, JAVA_REGISTRY_PATH + "\\" + current_java_version, access=winreg.KEY_READ | winreg.KEY_WOW64_64KEY), "JavaHome")[0]
                java_command = java_binary_path + "\\bin\\java.exe"
            except FileNotFoundError:
                java_command = str()
        else:
            java_command = "java"
        java_path = shutil.which(os.path.expanduser(os.path.expandvars(java_command)))
        if not java_path == None:
            java_path = os.path.abspath(java_path)

        return java_path

    def is_server_running(self):
        return self.server_running

    def set_launch_command(self, command):
        if ProcessManagerClass.JAVA_PATH_KEY in command:
            java_path = self._get_java_path()
            if java_path is None:
                LOG.error("Could not find Java on your system")
                return
            LOG.debug("Java path now: " + java_path)
            command = command.replace(ProcessManagerClass.JAVA_PATH_KEY, java_path)
        self.launch_command = command

    def launch_server(self):
        self.server_running = True
        LOG.info("Server is now starting")
        os.system(self.launch_command)
        LOG.info("Server has stopped")
        self.server_running = False

class MainGUI(QtGui.QMainWindow):
    def __init__(self):
        super(MainGUI, self).__init__()

        reloadconfig_button = QtGui.QPushButton('Reload Configuration')
        reloadconfig_button.clicked.connect(self._load_config)

        self.forcestartup_button = QtGui.QPushButton('Initiate Server Startup')
        self.forcestartup_button.clicked.connect(self._force_startup)

        self.setserveronline_button = QtGui.QPushButton("Toggle server online")
        self.setserveronline_button.clicked.connect(self._set_online)
        self.setserveronline_button.hide()

        self.setserveroffline_button = QtGui.QPushButton("Toggle server offline")
        self.setserveroffline_button.clicked.connect(self._set_offline)

        self.sendshutdown_button = QtGui.QPushButton('Exit after server shutdown')
        self.sendshutdown_button.clicked.connect(self._set_pending_shutdown)

        self.cancelsendshutdown_button = QtGui.QPushButton('Cancel exit after server shutdown')
        self.cancelsendshutdown_button.clicked.connect(self._cancel_pending_shutdown)
        self.cancelsendshutdown_button.hide()

        serveroffline_layout = QtGui.QHBoxLayout()
        serveroffline_layout.addWidget(QtGui.QLabel("Server Offline Message:"))
        self.serveroffline_textbox = QtGui.QLineEdit()
        self.serveroffline_textbox.setText(ConfigManager.get_kick_serveroffline())
        serveroffline_layout.addWidget(self.serveroffline_textbox)

        main_layout = QtGui.QVBoxLayout()
        main_layout.addWidget(reloadconfig_button)
        main_layout.addWidget(self.forcestartup_button)
        main_layout.addWidget(self.setserveronline_button)
        main_layout.addWidget(self.setserveroffline_button)
        main_layout.addWidget(self.sendshutdown_button)
        main_layout.addWidget(self.cancelsendshutdown_button)
        main_layout.addLayout(serveroffline_layout)
        main_layout.addStretch()

        mainlayoutwidget = QtGui.QWidget()
        mainlayoutwidget.setLayout(main_layout)

        self.setCentralWidget(mainlayoutwidget)
        self.setWindowTitle('Minecraft Server Manager')

    def _load_config(self):
        success = ConfigManager.load_configuration()
        if success:
            QtGui.QMessageBox.information(self, "Success", "The configuration has been reloaded successfully.")
        else:
            QtGui.QMessageBox.critical(self, "Failure", "The configuration could not be reloaded successfully.", QtGui.QMessageBox.Ok)

    def _force_startup(self):
        if ProcessManager.is_server_running():
            QtGui.QMessageBox.critical(self, "Failure", "The server is already up.", QtGui.QMessageBox.Ok)
        else:
            STATE.set_pending_forcestartup(True)
            tmpsocket = socket.socket()
            tmpsocket.connect((ConfigManager.get_host(), ConfigManager.get_port()))
            tmpsocket.close()
            del tmpsocket
            QtGui.QMessageBox.information(self, "Success", "Startup of the Minecraft server initiated.")

    def _set_online(self):
        self.setserveronline_button.hide()
        self.setserveroffline_button.show()
        STATE.set_temp_offline(False)
        QtGui.QMessageBox.information(self, "Success", "The manager is now in ONLINE mode.")

    def _set_offline(self):
        self.setserveronline_button.show()
        self.setserveroffline_button.hide()
        ConfigManager.set_kick_serveroffline(self.serveroffline_textbox.text())
        STATE.set_temp_offline(True)
        QtGui.QMessageBox.information(self, "Success", "The manager is now in OFFLINE mode.")

    def _set_pending_shutdown(self):
        self.sendshutdown_button.hide()
        if not ProcessManager.is_server_running():
            self.close()
        else:
            self.cancelsendshutdown_button.show()
            STATE.set_pending_shutdown(True)
            QtGui.QMessageBox.information(self, "Success", "The manager will exit after the server has shutdown.")

    def _cancel_pending_shutdown(self):
        self.sendshutdown_button.show()
        self.cancelsendshutdown_button.hide()
        STATE.set_pending_shutdown(False)
        QtGui.QMessageBox.information(self, "Success", "The manager will remain running.")

class ManagerStateClass:
    def __init__(self):
        self.pending_shutdown = False
        self.pending_forcestartup = False
        self.temp_offline = False

    def set_pending_shutdown(self, value):
        self.pending_shutdown = value

    def set_pending_forcestartup(self, value):
        self.pending_forcestartup = value

    def set_temp_offline(self, value):
        self.temp_offline = value

TEXT_ENCODING = "UTF-8"

STATE = ManagerStateClass()

LOG = logging.getLogger("MinecraftServerManager")
LOG.propagate = False

try:
    #socket.setdefaulttimeout(5.0)
    ProcessManager = ProcessManagerClass()
    ConfigManager = ConfigManagerClass()
    ConfigManager.load_configuration()
    NetworkManager = NetworkManagerClass()
    NetworkManager.start()
    app = QtGui.QApplication(sys.argv)
    Interface = MainGUI()
    Interface.show()
    return_value = app.exec_()
except:
    LOG.exception("Unexpected exception thrown")

logging.shutdown()
sys.exit(return_value)
