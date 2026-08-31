import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "kiryuuki.oma-netscan"
  ipcTarget: "kiryuuki.oma-netscan"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root

  readonly property color contentForeground: bar ? bar.foreground : Color.foreground
  readonly property color contentSubtle: Qt.rgba(contentForeground.r, contentForeground.g, contentForeground.b, 0.6)
  readonly property string contentFontFamily: bar ? bar.fontFamily : Style.font.family

  property var netscanData: hostWidget ? hostWidget.netscanState : ({
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

  property bool isScanning: hostWidget ? hostWidget.isScanning : false
  property int selectedIndex: 0
  property var expandedRepeaters: ({})
  property var deepScanResults: ({})
  property string deepScanTargetIp: ""
  property bool isDeepScanning: false
  property string copyNotice: ""

  function open() { root.controller.show() }
  function close() { root.controller.hide() }
  function toggle() { if (root.opened) close(); else open(); }
  function refresh() {
    if (hostWidget && hostWidget.refresh) hostWidget.refresh()
  }

  onOpenedChanged: {
    if (root.opened) {
      keyCatcher.forceActiveFocus()
      root.selectedIndex = 0
    }
  }

  // Copy helper process
  Process {
    id: copyProcess
    property string textToCopy: ""
    command: ["wl-copy", "--", textToCopy]
  }

  function copyText(val, label) {
    if (!val) return
    copyProcess.textToCopy = String(val)
    copyProcess.running = true
    root.copyNotice = "Copied " + label + " (" + val + ")"
    noticeTimer.restart()
  }

  Timer {
    id: noticeTimer
    interval: 2500
    onTriggered: root.copyNotice = ""
  }

  // Deep Scan Process
  Process {
    id: deepScanProc
    command: ["/usr/bin/python3", (Quickshell.env("HOME") || "") + "/.config/omarchy/plugins/kiryuuki.oma-netscan/scripts/netscan_engine.py", "--deep-scan", root.deepScanTargetIp]
    stdout: StdioCollector {
      id: deepScanOut
      waitForEnd: true
      onStreamFinished: {
        root.isDeepScanning = false
        try {
          var res = JSON.parse(deepScanOut.text)
          if (res && res.ip) {
            var updated = Object.assign({}, root.deepScanResults)
            updated[res.ip] = res
            root.deepScanResults = updated
          }
        } catch (e) {}
      }
    }
  }

  function triggerDeepScan(ip) {
    if (!ip || root.isDeepScanning) return
    root.deepScanTargetIp = ip
    root.isDeepScanning = true
    deepScanProc.running = true
  }

  function toggleRepeaterExpand(mac) {
    if (!mac) return
    var updated = Object.assign({}, root.expandedRepeaters)
    updated[mac] = !updated[mac]
    root.expandedRepeaters = updated
  }

  readonly property var visibleHosts: root.netscanData && root.netscanData.hosts ? root.netscanData.hosts : []

  function getSelectedHost() {
    if (visibleHosts && visibleHosts[root.selectedIndex]) {
      return visibleHosts[root.selectedIndex]
    }
    return null
  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(560))
    contentHeight: panel.fittedContentHeight(mainColumn.implicitHeight, Style.space(720))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onMoveRequested: function(dx, dy) {
        if (dy !== 0) {
          var maxIdx = Math.max(0, root.visibleHosts.length - 1)
          root.selectedIndex = Math.max(0, Math.min(maxIdx, root.selectedIndex + dy))
        }
      }
      onActivateRequested: {
        var h = root.getSelectedHost()
        if (h) {
          if (h.isRepeater) root.toggleRepeaterExpand(h.mac)
          else root.copyText(h.ip, "IP")
        }
      }
      onReturnRequested: {
        var h = root.getSelectedHost()
        if (h) {
          if (h.isRepeater) root.toggleRepeaterExpand(h.mac)
          else root.copyText(h.ip, "IP")
        }
      }
      onTextKey: function(t) {
        if (t === "r" || t === "R") root.refresh()
        else if (t === "d" || t === "D") {
          var h = root.getSelectedHost()
          if (h && !h.isRepeater && h.ip) root.triggerDeepScan(h.ip)
        } else if (t === "c" || t === "C") {
          var h = root.getSelectedHost()
          if (h && !h.isRepeater && h.ip) root.copyText(h.ip, "IP")
          else if (h && h.mac) root.copyText(h.mac, "MAC")
        } else if (t === "m" || t === "M") {
          var h = root.getSelectedHost()
          if (h && h.mac) root.copyText(h.mac, "MAC")
        } else if (t === "e" || t === "E") {
          var h = root.getSelectedHost()
          if (h && h.isRepeater) root.toggleRepeaterExpand(h.mac)
        }
      }

      Flickable {
        anchors.fill: parent
        contentWidth: mainColumn.width
        contentHeight: mainColumn.implicitHeight
        clip: true

        Column {
          id: mainColumn
          width: parent.width
          spacing: Style.space(12)
          topPadding: Style.space(14)
          bottomPadding: Style.space(14)
          leftPadding: Style.space(16)
          rightPadding: Style.space(16)

          // --- HEADER: TITLE & CONTROLS ---
          RowLayout {
            width: parent.width - Style.space(32)
            spacing: Style.space(8)

            RowLayout {
              Layout.fillWidth: true
              spacing: Style.space(8)

              Text {
                textFormat: Text.PlainText
                text: "󰛳"
                font.family: root.contentFontFamily
                font.pixelSize: Style.font.title
                color: Color.accent
              }

              ColumnLayout {
                spacing: 0
                Text {
                  textFormat: Text.PlainText
                  text: "LOCAL NETWORK RECON"
                  font.family: root.contentFontFamily
                  font.pixelSize: Style.font.body
                  font.bold: true
                  color: root.contentForeground
                }
                Text {
                  textFormat: Text.PlainText
                  text: root.netscanData.subnet + " · Gateway: " + root.netscanData.gatewayIp
                  font.family: root.contentFontFamily
                  font.pixelSize: Style.font.caption
                  color: root.contentSubtle
                }
              }
            }

            // Rescan Action Button
            BorderSurface {
              implicitWidth: Style.space(110)
              implicitHeight: Style.space(30)
              radius: Style.cornerRadius
              color: rescanMouse.containsMouse ? Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.2) : Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.1)
              borderSpec: Border.controlSpec("normal", Color.accent, Color.accent)

              RowLayout {
                anchors.centerIn: parent
                spacing: Style.space(6)
                Text {
                  textFormat: Text.PlainText
                  text: root.isScanning ? "󱑞" : "󰑐"
                  font.family: root.contentFontFamily
                  font.pixelSize: Style.font.caption
                  color: Color.accent
                }
                Text {
                  textFormat: Text.PlainText
                  text: root.isScanning ? "Scanning..." : "Rescan (r)"
                  font.family: root.contentFontFamily
                  font.pixelSize: Style.font.caption
                  font.bold: true
                  color: Color.accent
                }
              }

              MouseArea {
                id: rescanMouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: root.refresh()
              }
            }
          }

          // --- STATS BAR ---
          BorderSurface {
            width: parent.width - Style.space(32)
            implicitHeight: Style.space(32)
            radius: Style.cornerRadius
            color: Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.04)
            borderSpec: Border.controlSpec("normal", Qt.darker(root.contentForeground, 3.0), Color.accent)

            RowLayout {
              anchors.fill: parent
              anchors.leftMargin: Style.space(12)
              anchors.rightMargin: Style.space(12)
              spacing: Style.space(16)

              Text {
                textFormat: Text.PlainText
                text: "󰄲 " + (root.netscanData.distinctHostsCount || 0) + " Distinct Hosts"
                font.family: root.contentFontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                color: "#10b981"
              }

              Text {
                textFormat: Text.PlainText
                text: "󰀝 " + (root.netscanData.repeatersCount || 0) + " AP / Repeater (" + (root.netscanData.repeaterDevicesCount || 0) + " IPs)"
                font.family: root.contentFontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                color: "#f59e0b"
              }

              Item { Layout.fillWidth: true }

              Text {
                textFormat: Text.PlainText
                text: root.copyNotice ? root.copyNotice : ("Updated: " + (root.netscanData.updatedAt ? Math.round((Date.now()/1000 - root.netscanData.updatedAt)/60) + "m ago" : "just now"))
                font.family: root.contentFontFamily
                font.pixelSize: Style.font.caption
                font.bold: !!root.copyNotice
                color: root.copyNotice ? Color.accent : root.contentSubtle
              }
            }
          }

          // --- CAP_NET_RAW WARNING (IF PERMISSION MISSING) ---
          BorderSurface {
            visible: root.netscanData.hasCapError === true
            width: parent.width - Style.space(32)
            implicitHeight: capCol.implicitHeight + Style.space(16)
            radius: Style.cornerRadius
            color: Qt.rgba(0.94, 0.27, 0.27, 0.12)
            borderSpec: Border.controlSpec("focus", "#ef4444", "#ef4444")

            ColumnLayout {
              id: capCol
              anchors.fill: parent
              anchors.margins: Style.space(10)
              spacing: Style.space(4)

              Text {
                textFormat: Text.PlainText
                text: "󰚌 Missing arp-scan raw capability"
                font.family: root.contentFontFamily
                font.pixelSize: Style.font.bodySmall
                font.bold: true
                color: "#ef4444"
              }
              Text {
                textFormat: Text.PlainText
                text: "To enable high-speed direct hardware scans, grant raw socket capabilities once:"
                font.family: root.contentFontFamily
                font.pixelSize: Style.font.caption
                color: root.contentForeground
              }
              Rectangle {
                Layout.fillWidth: true
                height: Style.space(26)
                radius: 4
                color: "#1e1e2e"
                RowLayout {
                  anchors.fill: parent
                  anchors.leftMargin: 8
                  anchors.rightMargin: 8
                  Text {
                    textFormat: Text.PlainText
                    text: "sudo setcap cap_net_raw,cap_net_admin+eip $(which arp-scan)"
                    font.family: "Monospace"
                    font.pixelSize: 11
                    color: "#a6adc8"
                  }
                  Item { Layout.fillWidth: true }
                  Text {
                    textFormat: Text.PlainText
                    text: "󰆏 Copy"
                    font.family: root.contentFontFamily
                    font.pixelSize: 11
                    font.bold: true
                    color: Color.accent
                  }
                }
                MouseArea {
                  anchors.fill: parent
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.copyText("sudo setcap cap_net_raw,cap_net_admin+eip $(which arp-scan)", "Command")
                }
              }
            }
          }

          // --- DEVICE LIST ---
          Repeater {
            model: root.visibleHosts
            delegate: ColumnLayout {
              id: hostDelegate
              required property var modelData
              required property int index
              readonly property bool isSelected: root.selectedIndex === index
              readonly property bool isRepeater: !!modelData.isRepeater
              readonly property bool isExpanded: isRepeater && !!root.expandedRepeaters[modelData.mac]

              width: mainColumn.width - Style.space(32)
              spacing: Style.space(4)

              // Main Host or Repeater Header Card
              BorderSurface {
                Layout.fillWidth: true
                implicitHeight: hostCol.implicitHeight + Style.space(16)
                radius: Style.cornerRadius
                color: isSelected
                  ? Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.16)
                  : (hostMouse.containsMouse ? Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.06) : Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.02))
                borderSpec: Border.controlSpec(isSelected ? "focus" : "normal", isSelected ? Color.accent : Qt.darker(root.contentForeground, 2.5), Color.accent)

                ColumnLayout {
                  id: hostCol
                  anchors.fill: parent
                  anchors.margins: Style.space(10)
                  spacing: Style.space(6)

                  // Line 1: Type Icon, IP / Summary, Badges
                  RowLayout {
                    Layout.fillWidth: true
                    spacing: Style.space(8)

                    Text {
                      textFormat: Text.PlainText
                      text: modelData.typeIcon || "󰖩"
                      font.family: root.contentFontFamily
                      font.pixelSize: Style.font.title
                      color: isRepeater ? "#f59e0b" : (modelData.isGateway ? "#3b82f6" : Color.accent)
                    }

                    Text {
                      textFormat: Text.PlainText
                      text: isRepeater ? modelData.summary : (modelData.ip + (modelData.hostname ? " (" + modelData.hostname + ")" : ""))
                      font.family: root.contentFontFamily
                      font.pixelSize: Style.font.bodySmall
                      font.bold: true
                      color: root.contentForeground
                    }

                    // Role Badge
                    Rectangle {
                      height: Style.space(18)
                      implicitWidth: roleText.implicitWidth + Style.space(10)
                      radius: 4
                      color: isRepeater ? Qt.rgba(0.96, 0.62, 0.04, 0.2) : (modelData.isGateway ? Qt.rgba(0.23, 0.51, 0.96, 0.2) : Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.2))
                      Text {
                        id: roleText
                        anchors.centerIn: parent
                        textFormat: Text.PlainText
                        text: isRepeater ? "COLLAPSED AP" : (modelData.guessedType || "Generic")
                        font.family: root.contentFontFamily
                        font.pixelSize: 11
                        font.bold: true
                        color: isRepeater ? "#f59e0b" : (modelData.isGateway ? "#60a5fa" : Color.accent)
                      }
                    }

                    Item { Layout.fillWidth: true }

                    // Accordion arrow for Repeater
                    Text {
                      visible: isRepeater
                      textFormat: Text.PlainText
                      text: isExpanded ? "󰅃 Collapse (e)" : "󰅀 Expand (e)"
                      font.family: root.contentFontFamily
                      font.pixelSize: Style.font.caption
                      font.bold: true
                      color: "#f59e0b"
                    }
                  }

                  // Line 2: Vendor, MAC, Latency, Open Ports
                  RowLayout {
                    Layout.fillWidth: true
                    spacing: Style.space(12)

                    Text {
                      textFormat: Text.PlainText
                      text: "MAC: " + (modelData.mac || "N/A")
                      font.family: "Monospace"
                      font.pixelSize: 11
                      color: root.contentSubtle
                    }

                    Text {
                      textFormat: Text.PlainText
                      text: "Vendor: " + (modelData.vendor || "Unknown")
                      font.family: root.contentFontFamily
                      font.pixelSize: 11
                      color: root.contentSubtle
                    }

                    Item { Layout.fillWidth: true }

                    // Open Ports tags
                    Row {
                      spacing: 4
                      visible: !isRepeater && modelData.openPorts && modelData.openPorts.length > 0
                      Repeater {
                        model: (modelData.openPorts || []).slice(0, 5)
                        delegate: Rectangle {
                          height: 16
                          implicitWidth: portText.implicitWidth + 8
                          radius: 3
                          color: Qt.rgba(0.06, 0.72, 0.51, 0.16)
                          Text {
                            id: portText
                            anchors.centerIn: parent
                            textFormat: Text.PlainText
                            text: String(modelData)
                            font.family: "Monospace"
                            font.pixelSize: 10
                            color: "#10b981"
                          }
                        }
                      }
                    }
                  }

                  // Deep scan inline result
                  BorderSurface {
                    visible: !isRepeater && !!root.deepScanResults[modelData.ip]
                    Layout.fillWidth: true
                    implicitHeight: deepScanResultCol.implicitHeight + 12
                    radius: 4
                    color: "#181825"
                    borderSpec: Border.controlSpec("normal", "#313244", "#89b4fa")

                    ColumnLayout {
                      id: deepScanResultCol
                      anchors.fill: parent
                      anchors.margins: 8
                      spacing: 4
                      Text {
                        textFormat: Text.PlainText
                        text: "󰋚 Deep Scan Inspection:"
                        font.family: root.contentFontFamily
                        font.pixelSize: 11
                        font.bold: true
                        color: "#89b4fa"
                      }
                      Text {
                        textFormat: Text.PlainText
                        text: (root.deepScanResults[modelData.ip] && root.deepScanResults[modelData.ip].raw) ? root.deepScanResults[modelData.ip].raw : "No extra services identified."
                        font.family: "Monospace"
                        font.pixelSize: 10
                        color: "#cdd6f4"
                      }
                    }
                  }
                }

                MouseArea {
                  id: hostMouse
                  anchors.fill: parent
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: {
                    root.selectedIndex = index
                    if (isRepeater) root.toggleRepeaterExpand(modelData.mac)
                    else root.copyText(modelData.ip, "IP")
                  }
                }
              }

              // Collapsible Downstream Devices Grid (for Repeaters)
              ColumnLayout {
                visible: isExpanded
                Layout.fillWidth: true
                Layout.leftMargin: Style.space(16)
                spacing: Style.space(4)

                Repeater {
                  model: modelData.downstreamHosts || []
                  delegate: BorderSurface {
                    required property var modelData
                    Layout.fillWidth: true
                    implicitHeight: Style.space(32)
                    radius: 4
                    color: downMouse.containsMouse ? Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.08) : Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.03)
                    borderSpec: Border.controlSpec("normal", Qt.darker(root.contentForeground, 3.5), Color.accent)

                    RowLayout {
                      anchors.fill: parent
                      anchors.leftMargin: Style.space(10)
                      anchors.rightMargin: Style.space(10)
                      spacing: Style.space(8)

                      Text {
                        textFormat: Text.PlainText
                        text: modelData.typeIcon || "󰖩"
                        font.family: root.contentFontFamily
                        font.pixelSize: Style.font.bodySmall
                        color: "#f59e0b"
                      }

                      Text {
                        textFormat: Text.PlainText
                        text: modelData.ip
                        font.family: root.contentFontFamily
                        font.pixelSize: Style.font.caption
                        font.bold: true
                        color: root.contentForeground
                      }

                      Text {
                        textFormat: Text.PlainText
                        text: modelData.guessedType || "Generic Device"
                        font.family: root.contentFontFamily
                        font.pixelSize: 11
                        color: root.contentSubtle
                      }

                      Item { Layout.fillWidth: true }

                      Text {
                        textFormat: Text.PlainText
                        text: "󰆏 Copy"
                        font.family: root.contentFontFamily
                        font.pixelSize: 11
                        font.bold: true
                        color: Color.accent
                      }
                    }

                    MouseArea {
                      id: downMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      cursorShape: Qt.PointingHandCursor
                      onClicked: root.copyText(modelData.ip, "Downstream IP")
                    }
                  }
                }
              }
            }
          }

          // --- FOOTER SHORTCUTS ---
          BorderSurface {
            width: parent.width - Style.space(32)
            implicitHeight: Style.space(32)
            radius: Style.cornerRadius
            color: Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.02)
            borderSpec: Border.controlSpec("normal", Qt.darker(root.contentForeground, 3.0), Color.accent)

            RowLayout {
              anchors.centerIn: parent
              spacing: Style.space(12)

              Text {
                textFormat: Text.PlainText
                text: "[r] Rescan  ·  [d] Deep Scan  ·  [c] Copy IP  ·  [m] Copy MAC  ·  [e] Toggle Repeater  ·  [Esc] Close"
                font.family: root.contentFontFamily
                font.pixelSize: 11
                color: root.contentSubtle
              }
            }
          }
        }
      }
    }
  }
}
