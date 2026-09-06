import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

BarWidget {
  id: root
  moduleName: "kiryuuki.oma-netscan"

  readonly property string stateDir: (Quickshell.env("HOME") || "") + "/.local/state/omarchy/netscan"
  readonly property string stateFilePath: stateDir + "/devices.json"
  readonly property string enginePath: (Quickshell.env("HOME") || "") + "/.config/omarchy/plugins/kiryuuki.oma-netscan/scripts/netscan_engine.py"

  // The range the user picked in the panel; empty follows the default route.
  readonly property string scanSubnet: (settings && typeof settings.scanSubnet === "string") ? settings.scanSubnet : ""

  property var netscanState: ({
    updatedAt: 0,
    subnet: "192.168.100.0/24",
    gatewayIp: "192.168.100.1",
    gatewayOnline: true,
    totalHosts: 0,
    distinctHostsCount: 0,
    repeaterDevicesCount: 0,
    repeatersCount: 0,
    securityWarningsCount: 0,
    greenCount: 0,
    orangeCount: 0,
    redCount: 0,
    hasCapError: false,
    hosts: []
  })

  property bool isScanning: false
  readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false

  // The engine's --list-networks document: { defaultIface, defaultGateway,
  // networks: [{ iface, ip, cidr, gateway, kind, isDefault }] }. Null until
  // the first listing has returned.
  property var networks: null

  function injectPanel() {
    var target = panelLoader.item
    if (!target) return
    if ("bar" in target) target.bar = root.bar
    if ("settings" in target) target.settings = root.settings
    if ("anchorItem" in target) target.anchorItem = button
    if ("hostWidget" in target) target.hostWidget = root
    if ("netscanData" in target) target.netscanData = root.netscanState
    if ("isScanning" in target) target.isScanning = root.isScanning
    if ("networks" in target) target.networks = root.networks
    if ("scanSubnet" in target) target.scanSubnet = root.scanSubnet
  }

  function refresh() {
    if (root.isScanning) return
    root.refreshNetworks()
    root.isScanning = true
    scanProcess.running = true
  }

  function refreshNetworks() {
    if (listProcess.running) return
    listProcess.running = true
  }

  // Read-modify-write of this widget's inline shell.json entry, so a choice
  // made in the panel survives a shell restart.
  function persistSettings(values) {
    var entry = { id: root.moduleName }
    for (var existing in root.settings) if (existing !== "id") entry[existing] = root.settings[existing]
    for (var key in values) entry[key] = values[key]
    root.settings = entry
    if (root.bar && root.bar.shell && typeof root.bar.shell.updateEntryInline === "function")
      root.bar.shell.updateEntryInline(root.moduleName, entry)
  }

  function selectSubnet(cidr) {
    if (cidr === root.scanSubnet) return
    root.persistSettings({ scanSubnet: cidr })
    root.injectPanel()
    root.refresh()
  }

  function setRefreshInterval(m) {
    root.persistSettings({ refreshIntervalMin: m })
    autoScanTimer.interval = Math.max(1, m) * 60 * 1000
  }

  function togglePanel() {
    if (panelLoader.item && panelLoader.item.toggle) panelLoader.item.toggle()
  }

  function open() {
    if (panelLoader.item && panelLoader.item.open) panelLoader.item.open()
  }

  function close() {
    if (panelLoader.item && panelLoader.item.close) panelLoader.item.close()
  }

  implicitWidth: button.slotSize + Style.space(2)
  implicitHeight: button.implicitHeight

  onBarChanged: injectPanel()
  onSettingsChanged: {
    injectPanel()
    if (root.settings && root.settings.refreshIntervalMin) {
      autoScanTimer.interval = Math.max(1, root.settings.refreshIntervalMin) * 60 * 1000
    }
  }

  FileView {
    id: stateFile
    path: root.stateFilePath
    watchChanges: true
    printErrors: false
    onLoaded: {
      try {
        var parsed = JSON.parse(text())
        if (parsed && typeof parsed === "object") {
          root.netscanState = parsed
          root.injectPanel()
        }
      } catch (e) {}
    }
  }

  Process {
    id: scanProcess
    command: root.scanSubnet !== ""
      ? ["/usr/bin/python3", root.enginePath, "--scan", "--subnet", root.scanSubnet]
      : ["/usr/bin/python3", root.enginePath, "--scan"]
    onExited: function(code) {
      root.isScanning = false
      stateFile.reload()
      root.injectPanel()
    }
  }

  Process {
    id: listProcess
    command: ["/usr/bin/python3", root.enginePath, "--list-networks"]
    stdout: StdioCollector {
      id: listOut
      waitForEnd: true
      onStreamFinished: {
        try {
          var parsed = JSON.parse(listOut.text)
          if (parsed && typeof parsed === "object" && Array.isArray(parsed.networks)) {
            root.networks = parsed
            root.injectPanel()
          }
        } catch (e) {}
      }
    }
  }

  Timer {
    id: initialScanTimer
    interval: 600
    running: true
    repeat: false
    onTriggered: {
      if (!root.netscanState || !root.netscanState.updatedAt) {
        root.refresh()
      }
    }
  }

  Timer {
    id: autoScanTimer
    interval: (root.settings && root.settings.refreshIntervalMin ? Math.max(1, root.settings.refreshIntervalMin) : 15) * 60 * 1000
    running: root.settings && ("autoRefresh" in root.settings) ? root.settings.autoRefresh : true
    repeat: true
    onTriggered: root.refresh()
  }

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
  }

  IpcHandler {
    target: "kiryuuki.oma-netscan"

    function refresh(): void { root.refresh() }
    function open(): void { root.open() }
    function close(): void { root.close() }
    function toggle(): void { root.togglePanel() }
  }

  BarIconButton {
    id: button
    bar: root.bar
    slotSize: Style.space(38)
    opticalSize: Style.space(34)
    foreground: root.opened
      ? Color.accent
      : (root.netscanState.hasCapError
          ? "#ef4444"
          : (root.netscanState.securityWarningsCount > 0
              ? "#ef4444"
              : (root.bar ? root.bar.barForeground : Color.foreground)))

    iconComponent: Component {
      Row {
        anchors.centerIn: parent
        spacing: Style.space(3)

        Text {
          textFormat: Text.PlainText
          text: root.isScanning ? "󱑞" : "󰛳"
          font.family: root.bar ? root.bar.fontFamily : Style.font.family
          font.pixelSize: Style.font.body
          color: root.opened
            ? Color.accent
            : (root.netscanState.hasCapError
                ? "#ef4444"
                : (root.bar ? root.bar.barForeground : Color.foreground))
          anchors.verticalCenter: parent.verticalCenter
        }

        Text {
          textFormat: Text.PlainText
          text: String(root.netscanState.distinctHostsCount || root.netscanState.totalHosts || "·")
          font.family: "Monospace"
          font.pixelSize: 11
          font.bold: true
          color: root.opened
            ? Color.accent
            : (root.netscanState.hasCapError
                ? "#ef4444"
                : (root.bar ? root.bar.barForeground : Color.foreground))
          anchors.verticalCenter: parent.verticalCenter
        }
      }
    }

    tooltipText: root.netscanState.hasCapError
      ? "OmaNetscan: Missing cap_net_raw permission"
      : ("OmaNetscan: " + (root.netscanState.distinctHostsCount || 0) + " active network hosts (" + (root.netscanState.repeaterDevicesCount || 0) + " idle devices behind AP) on " + (root.netscanState.subnet || "LAN"))

    onPressed: function(b) {
      if (!root.bar) return
      if (b === Qt.MiddleButton) root.refresh()
      else root.togglePanel()
    }
  }
}
