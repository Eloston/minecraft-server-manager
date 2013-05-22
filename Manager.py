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
import os.path

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
        self.SETOFFLINE = None

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
        elif kicktype.lower() == 'serveroffline':
            kickmessage = self.KICKMESSAGE_DICT['serveroffline']
        self.CLIENTSOCKET.sendall(header + self.makeMCstring(kickmessage))

    def receive(self):
        '''
        Reads data sent from a client.
        If the client wants to join (sends a 0x02, Handshake) this returns True, otherwise False will be returned.
        However if a whitelist is enabled in the manager than the client has to be whitelisted first.
        '''
        loopcount = 0
        while not loopcount == 7:
            print("Getting client data")
            try:
                tmprecv = self.CLIENTSOCKET.recv(512)
            except Exception, error:
                print("***Error while getting client data:", str(error))
            if len(tmprecv) > 0:
                header = struct.unpack('B', tmprecv[:1])[0]
                tmprecv = tmprecv[1:]
                break
            else:
                loopcount += 1
                time.sleep(0.05)
        if loopcount == 7:
            print("Reached loop limit")
            return False
        if header == 0xFE:
            print("Got pinged")
            self.sendPingResponse()
            return False

        elif header == 0x02:
            print("Player is trying to connect")
            clientprotocolversion = str(struct.unpack('B', tmprecv[:1])[0])
            tmprecv = tmprecv[1:]
            if clientprotocolversion > self.PROTOCOLVER:
                print("Player disconnected for older server")
                self.sendKickMessage('serverolder')
                return False

            elif clientprotocolversion < self.PROTOCOLVER:
                print("Player disconnected for older client")
                self.sendKickMessage('clientolder')
                return False

            elif clientprotocolversion == self.PROTOCOLVER:
                if self.SETOFFLINE:
                    print("Server is offline")
                    self.sendKickMessage('serveroffline')
                    return False

                if self.WHITELIST:
                    clientusername = self.getMCstring(tmprecv).lower()
                    print("Using whitelist. Player "+clientusername+" connected.")
                    if clientusername in self.WHITELIST:
                        self.sendKickMessage('startup')
                        print("Ready to startup server")
                        return True
                    else:
                        self.sendKickMessage('notwhitelist')
                        print("Player is not in whitelist")
                        return False
                else:
                    self.sendKickMessage('startup')
                    print("Ready to startup server")
                    return True

        else:
            print("I got junk...?! Data: "+str(tmprecv))
            return False

    def checkStartup(self, clientobj, setoffline):
        self.start(clientobj)
        print("Started client socket object")
        self.SETOFFLINE = setoffline
        isGood = self.receive()
        self.stop()
        print("Stopped client socket object")
        return isGood

    def start(self, clientobj):
        self.CLIENTSOCKET = clientobj
        self.CLIENTSOCKET.setblocking(True)

    def stop(self):
        self.CLIENTSOCKET.shutdown(socket.SHUT_RDWR)
        self.CLIENTSOCKET.close()

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
        self.ISSERVERUP = False
        self.SETOFFLINE = False
        self.FORCESTARTUP = False

    def setSocketInfo(self):
        self.SOCKET = socket.socket()
        self.SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.SOCKET.bind((self.HOST, self.PORT))

    def startServer(self):
        self.ISSERVERUP = True
        os.system(self.STARTUPCOMMAND)
        self.ISSERVERUP = False

    def readWhitelist(self, path):
        whitelist = open(path).read().split('\n')
        self.WHITELIST = whitelist

    def readConfig(self):
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
                kickmessagedict = {'startup': config["ServerManagerConfiguration"]['KickMessage-Startup'], 'serverolder': config["ServerManagerConfiguration"]['KickMessage-ServerOlder'], 'clientolder': config["ServerManagerConfiguration"]['KickMessage-ClientOlder'], 'notwhitelist': config["ServerManagerConfiguration"]['KickMessage-NotWhiteListed'], 'serveroffline': config["ServerManagerConfiguration"]["KickMessage-ServerOffline"]}
                protocolver = config["ServerManagerConfiguration"]['ProtocolVersion']
                mcver = config["ServerManagerConfiguration"]['MinecraftVersion']
                onlineplayers = config["ServerManagerConfiguration"]['OnlinePlayers']
            except:
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
            print("Going to listen")
            self.SOCKET.listen(5)
            print("Got connection from someone")
            if self.FORCESTARTUP:
                print("Got hacky connection from myself")
                willStartup = True
                self.FORCESTARTUP = False
            else:
                print("Someone externally connected, or just waiting for external connections")
                clientsocket = self.SOCKET.accept()[0]
                print("Accepted client socket")
                managerobj = MCmanager(self.PINGLIST, self.WHITELIST, self.KICKMESSAGE_DICT)
                print("Initiated manager object")
                willStartup = managerobj.checkStartup(clientsocket, self.SETOFFLINE)

            if willStartup:
                self.SOCKET.close()
                print("Starting up server")
                self.startServer()

            if self.SHUTDOWN:
                print("Shutting down...")
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
        self.MAINCLASSTHREAD.daemon = True

        reloadconfigbutton = QtGui.QPushButton('Reload Configuration')
        reloadconfigbutton.clicked.connect(self.loadConfig)

        self.startbutton = QtGui.QPushButton('Start Manager')
        self.startbutton.clicked.connect(self.start)

        self.forcestartupbutton = QtGui.QPushButton('Initiate Server Startup')
        self.forcestartupbutton.clicked.connect(self.forcestartup)
        self.forcestartupbutton.hide()

        self.setserveronline = QtGui.QPushButton("Toggle server online")
        self.setserveronline.clicked.connect(self.setonline)
        self.setserveronline.hide()

        self.setserveroffline = QtGui.QPushButton("Toggle server offline")
        self.setserveroffline.clicked.connect(self.setoffline)
        self.setserveroffline.hide()

        self.sendshutdownbutton = QtGui.QPushButton('Exit after server shutdown')
        self.sendshutdownbutton.clicked.connect(self.shutdown)
        self.sendshutdownbutton.hide()

        self.cancelsendshutdownbutton = QtGui.QPushButton('Cancel exit after server shutdown')
        self.cancelsendshutdownbutton.clicked.connect(self.cancelshutdown)
        self.cancelsendshutdownbutton.hide()

        mainlayout = QtGui.QVBoxLayout()
        mainlayout.addWidget(reloadconfigbutton)
        mainlayout.addWidget(self.startbutton)
        mainlayout.addWidget(self.forcestartupbutton)
        mainlayout.addWidget(self.setserveronline)
        mainlayout.addWidget(self.setserveroffline)
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
        self.setserveroffline.show()
        self.sendshutdownbutton.show()
        self.forcestartupbutton.show()
        readsuccess = self.MAINCLASS.readConfig()
        if readsuccess:
            self.MAINCLASSTHREAD.start()
            QtGui.QMessageBox.information(self, "Sucess", "Startup complete.")
        else:
            QtGui.QMessageBox.critical(self, "Failure", "An error encountered while reading configuration files.", QtGui.QMessageBox.Ok)
            self.close()

    def forcestartup(self):
        if self.MAINCLASS.ISSERVERUP:
            QtGui.QMessageBox.critical(self, "Failure", "The server is already up.", QtGui.QMessageBox.Ok)
        else:
            self.MAINCLASS.FORCESTARTUP = True
            tmpsocket = socket.socket()
            tmpsocket.connect((self.MAINCLASS.HOST, self.MAINCLASS.PORT))
            tmpsocket.send(bytes("a", "UTF-8)"))
            tmpsocket.close()
            del tmpsocket
            QtGui.QMessageBox.information(self, "Sucess", "Startup of the Minecraft server initiated.")

    def setonline(self):
        self.setserveronline.hide()
        self.setserveroffline.show()
        self.MAINCLASS.SETOFFLINE = False
        QtGui.QMessageBox.information(self, "Sucess", "The manager is now in ONLINE mode.")

    def setoffline(self):
        self.setserveronline.show()
        self.setserveroffline.hide()
        self.MAINCLASS.SETOFFLINE = True
        QtGui.QMessageBox.information(self, "Sucess", "The manager is now in OFFLINE mode.")

    def shutdown(self):
        self.sendshutdownbutton.hide()
        if not self.MAINCLASS.ISSERVERUP:
            self.close()
        else:
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

    oldpath = os.getcwd()

    os.chdir(os.path.dirname(__file__))

    interface = guiinterface()
    interface.show()

    os.chdir(oldpath)

    sys.exit(app.exec_())
