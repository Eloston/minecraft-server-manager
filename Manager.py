# Minecraft Server Manager
# Developed by Eloston
# Consult the README for additional details

from PySide import QtCore, QtGui

import socket
import struct
import time
import configparser
import threading
import os

class MCmanager:
    def __init__(self, pinglist, whitelist, kickmessagedict):
        self.BEGINNING = chr(0xA7) + '1'
        self.SEPARATOR = chr(0x00)

        self.PROTOCOLVER = pinglist[0]
        self.MCVERSION = pinglist[1]
        self.MOTD = pinglist[2]
        self.ONLINEPLAYERS = pinglist[3]
        self.MAXPLAYERS = pinglist[4]
        self.KICKMESSAGE_DICT = kickmessagedict
        self.WHITELIST = whitelist

        self.CLIENTSOCKET = None

    def makeMCstring(self, string):
        length = struct.pack('!h', len(string))
        string = string.encode('UTF-16be')

        return length + string

    def getMCstring(self, data):
        length = struct.unpack('!h', data[:2])[0]
        data = data[2:]
        string = data[:length*2].decode('UTF-16be')
        return string

    def makeHeader(self, value):
        return struct.pack('B', value)

    def sendPingResponse(self):
        infostring = self.makeMCstring(self.BEGINNING + self.SEPARATOR + self.PROTOCOLVER + self.SEPARATOR + self.MCVERSION + self.SEPARATOR + self.MOTD + self.SEPARATOR + self.ONLINEPLAYERS + self.SEPARATOR + self.MAXPLAYERS)
        header = self.makeHeader(0xFF)
        self.CLIENTSOCKET.sendall(header + infostring)

    def sendKickMessage(self, kicktype):
        header = self.makeHeader(0xFF)
        if kicktype.lower() == 'startup':
            kickmessage = self.KICKMESSAGE_DICT['startup']
        elif kicktype.lower() == 'serverolder':
            kickmessage = self.KICKMESSAGE_DICT['serverolder']
        elif kicktype.lower() == 'clientolder':
            kickmessage = self.KICKMESSAGE_DICT['clientolder']
        elif kicktype.lower() == 'notwhitelist':
            kickmessage = self.KICKMESSAGE_DICT['notwhitelist']
        print(self.makeMCstring(kickmessage))
        self.CLIENTSOCKET.sendall(header + self.makeMCstring(kickmessage))

    def receive(self):
        '''
        Reads data sent from a client.
        If the client wants to join (sends a 0x02, Handshake) this returns True, otherwise False will be returned.
        '''
        while True:
            tmprecv = self.CLIENTSOCKET.recv(512)
            if len(tmprecv) > 0:
                header = struct.unpack('B', tmprecv[:1])[0]
                tmprecv = tmprecv[1:]
                break
            else:
                time.sleep(0.05)
        if header == 0xFE:
            self.sendPingResponse()
            return False

        elif header == 0x02:
            clientprotocolversion = str(struct.unpack('B', tmprecv[:1])[0])
            tmprecv = tmprecv[1:]
            if clientprotocolversion > self.PROTOCOLVER:
                self.sendKickMessage('serverolder')
                return False

            elif clientprotocolversion < self.PROTOCOLVER:
                self.sendKickMessage('clientolder')
                return False

            elif clientprotocolversion == self.PROTOCOLVER:
                if self.WHITELIST:
                    clientusername = self.getMCstring(tmprecv).lower()
                    if clientusername in self.WHITELIST:
                        self.sendKickMessage('startup')
                        return True
                    else:
                        self.sendKickMessage('notwhitelist')
                        return False
                else:
                    self.sendKickMessage('startup')
                    return True

        else:
            return False

    def start(self, clientobj):
        self.CLIENTSOCKET = clientobj
        self.CLIENTSOCKET.setblocking(True)
        willStartup = self.receive()
        self.CLIENTSOCKET.shutdown(socket.SHUT_RDWR)
        self.CLIENTSOCKET.close()
        return willStartup

class main:
    def __init__(self, uiobj):
        self.UICLASS = uiobj
        self.SOCKET = None
        self.PINGLIST = None
        self.KICKMESSAGE_DICT = None
        self.HOST = None
        self.PORT = None
        self.STARTUPCOMMAND = None
        self.SHUTDOWN = False
        self.WHITELIST = None

    def setSocketInfo(self):
        self.SOCKET = socket.socket()
        self.SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.SOCKET.bind((self.HOST, self.PORT))

    def startServer(self):
        os.system(self.STARTUPCOMMAND)

    def readWhitelist(self, path):
        whitelist = open(path).read().split('\n')
        self.WHITELIST = whitelist

    def readConfig(self, configfile='config.ini'):
        '''
        Reads a configuration file and loads in parameters.
        Returns True if all the parameters could be read, otherwise returns False
        '''
        config = configparser.ConfigParser()
        config.read('config.ini')
        if len(config.sections()) == 1 and config.sections()[0] == "ServerManagerConfiguration":
            try:
                if config.getboolean('ServerManagerConfiguration', 'UseServerProperties'):
                    path = config['ServerManagerConfiguration']['ServerPropertiesFile']
                    serverproperties = configparser.ConfigParser()
                    serverproperties.read_string('['+configparser.DEFAULTSECT+']\n'+open(path).read())
                    host = serverproperties[configparser.DEFAULTSECT]['server-ip']
                    port = serverproperties.getint(configparser.DEFAULTSECT, 'server-port')
                    motd = serverproperties[configparser.DEFAULTSECT]['motd']
                    maxplayers = serverproperties[configparser.DEFAULTSECT]['max-players']
                else:
                    host = config["ServerManagerConfiguration"]['Host']
                    port = config.getint("ServerManagerConfiguration", 'Port')
                    motd = config["ServerManagerConfiguration"]['MessageOfTheDay']
                    maxplayers = config["ServerManagerConfiguration"]['MaxPlayers']
                if config.getboolean('ServerManagerConfiguration', 'UseWhiteList'):
                    self.readWhitelist(config['ServerManagerConfiguration']['WhiteListFile'])
                startupcommand = config["ServerManagerConfiguration"]['StartupCommand']
                kickmessagedict = {'startup': config["ServerManagerConfiguration"]['KickMessage-Startup'], 'serverolder': config["ServerManagerConfiguration"]['KickMessage-ServerOlder'], 'clientolder': config["ServerManagerConfiguration"]['KickMessage-ClientOlder'], 'notwhitelist': config["ServerManagerConfiguration"]['KickMessage-NotWhiteListed']}
                protocolver = config["ServerManagerConfiguration"]['ProtocolVersion']
                mcver = config["ServerManagerConfiguration"]['MinecraftVersion']
                onlineplayers = config["ServerManagerConfiguration"]['OnlinePlayers']
            except KeyError:
                return False

            except ValueError:
                return False

            self.HOST = host
            self.PORT = port
            self.STARTUPCOMMAND = startupcommand
            self.KICKMESSAGE_DICT = kickmessagedict
            self.PINGLIST = [protocolver, mcver, motd, onlineplayers, maxplayers]
            return True
        else:
            return False

    def start(self):
        self.setSocketInfo()
        while True:
            self.SOCKET.listen(5)
            clientsocket = self.SOCKET.accept()[0]
            willStartup = MCmanager(self.PINGLIST, self.WHITELIST, self.KICKMESSAGE_DICT).start(clientsocket)
            if willStartup:
                self.SOCKET.close()
                os.system('ss -lnp')
                self.startServer()

            if self.SHUTDOWN:
                self.SOCKET.close()
                self.UICLASS.close()
                break
            else:
                if willStartup:
                    while True:
                        try:
                            self.setSocketInfo()
                        except socket.error:
                            del self.SOCKET
                            time.sleep(1)
                            continue
                        print("Sucessfully Bound to Socket")
                        break

class guiinterface(QtGui.QMainWindow):
    def __init__(self):
        super(guiinterface, self).__init__()

        self.MAINCLASS = main(self)

        self.MAINCLASSTHREAD = threading.Thread(target=self.MAINCLASS.start)

        reloadconfigbutton = QtGui.QPushButton('Reload Configuration')
        reloadconfigbutton.clicked.connect(self.loadConfig)

        self.startbutton = QtGui.QPushButton('Start')
        self.startbutton.clicked.connect(self.start)

        self.sendshutdownbutton = QtGui.QPushButton('Exit after server shutdown')
        self.sendshutdownbutton.clicked.connect(self.shutdown)
        self.sendshutdownbutton.hide()

        self.cancelsendshutdownbutton = QtGui.QPushButton('Cancel exit after server shutdown')
        self.cancelsendshutdownbutton.clicked.connect(self.cancelshutdown)
        self.cancelsendshutdownbutton.hide()

        mainlayout = QtGui.QVBoxLayout()
        mainlayout.addWidget(reloadconfigbutton)
        mainlayout.addWidget(self.startbutton)
        mainlayout.addWidget(self.sendshutdownbutton)
        mainlayout.addWidget(self.cancelsendshutdownbutton)

        mainlayoutwidget = QtGui.QWidget()
        mainlayoutwidget.setLayout(mainlayout)

        self.setCentralWidget(mainlayoutwidget)
        self.setWindowTitle('Minecraft Server Manager')

    def loadConfig(self):
        sucess = self.MAINCLASS.readConfig()
        if sucess:
            QtGui.QMessageBox.information(self, "Sucess", "The configuration has been reloaded sucessfully.")
        else:
            QtGui.QMessageBox.critical(self, "Failure", "The configuration could not be reloaded sucessfully.", QtGui.QMessageBox.Ok)

    def start(self):
        self.startbutton.hide()
        self.sendshutdownbutton.show()
        self.MAINCLASS.readConfig()
        self.MAINCLASSTHREAD.start()
        QtGui.QMessageBox.information(self, "Sucess", "Startup complete.")

    def shutdown(self):
        self.sendshutdownbutton.hide()
        self.cancelsendshutdownbutton.show()
        self.MAINCLASS.SHUTDOWN = True
        QtGui.QMessageBox.information(self, "Sucess", "The manager will exit after the server has shutdown.")

    def cancelshutdown(self):
        self.sendshutdownbutton.show()
        self.cancelsendshutdownbutton.hide()
        self.MAINCLASS.SHUTDOWN = False
        QtGui.QMessageBox.information(self, "Sucess", "The manager will remain running.")

if __name__ == '__main__':
    import sys

    app = QtGui.QApplication(sys.argv)

    interface = guiinterface()
    interface.show()

    sys.exit(app.exec_())
