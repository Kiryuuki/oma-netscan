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

  property var netscanState: ({
    updatedAt: 0,
    subnet: "192.168.100.0/24",
    gatewayIp: "192.168.100.1",
    gatewayOnline: true,
    totalHosts: 0,
    distinctHostsCount: 0,
    repeaterDevicesCount: 0,
    repeatersCount: 0,
    hasCapError: false,
    hosts: []
  })

  property bool isScanning: false
  readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false

  function injectPanel() {
    var target = panelLoader.item
    if (!target) return
    if ("bar" in target) target.bar = root.bar
    if ("settings" in target) target.settings = root.settings
    if ("anchorItem" in target) target.anchorItem = button
    if ("hostWidget" in target) target.hostWidget = root
    if ("netscanData" in target) target.netscanData = root.netscanState
    if ("isScanning" in target) target.isScanning = root.isScanning
  }

  function refresh() {
    if (root.isScanning) return
    root.isScanning = true
    scanProcess.running = true
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

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onBarChanged: injectPanel()
  onSettingsChanged: injectPanel()

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
    command: ["/usr/bin/python3", (Quickshell.env("HOME") || "") + "/.config/omarchy/plugins/kiryuuki.oma-netscan/scripts/netscan_engine.py", "--scan"]
    onExited: function(code) {
      root.isScanning = false
      stateFile.reload()
      root.injectPanel()
    }
  }

  // Auto-scan once on startup if state file is missing or older than 10 mins
  Component.onCompleted: {
    if (!root.netscanState.updatedAt || (Date.now() / 1000 - root.netscanState.updatedAt) > 600) {
      root.refresh()
    }
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
    anchors.fill: parent
    bar: root.bar
    text: root.isScanning ? "󱑞" : "󰛳 " + (root.netscanState.distinctHostsCount || root.netscanState.totalHosts || "·")
    foreground: root.opened
      ? Color.accent
      : (root.netscanState.hasCapError
          ? "#ef4444"
          : (root.bar ? root.bar.barForeground : Color.foreground))
    slotSize: Style.bar.statusSlot
    tooltipText: root.netscanState.hasCapError
      ? "OmaNetscan: Missing cap_net_raw permission"
      : ("OmaNetscan: " + root.netscanState.distinctHostsCount + " hosts (" + root.netscanState.repeaterDevicesCount + " behind AP) on " + root.netscanState.subnet)

    onPressed: function(b) {
      if (!root.bar) return
      if (b === Qt.MiddleButton) root.refresh()
      else root.togglePanel()
    }
  }
}
