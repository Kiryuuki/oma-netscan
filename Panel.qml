import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "kiryuuki.oma-netscan"

  property var anchorItem: null
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root

  readonly property color contentForeground: bar ? bar.foreground : Color.foreground
  readonly property color contentSubtle: Qt.rgba(contentForeground.r, contentForeground.g, contentForeground.b, 0.6)
  readonly property string contentFontFamily: bar ? bar.fontFamily : Style.font.family

  property var netscanData: hostWidget ? hostWidget.netscanState : ({
    updatedAt: 0,
    subnet: "192.168.100.0/24",
    localIp: "192.168.100.3",
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

  property bool isScanning: hostWidget ? hostWidget.isScanning : false
  property string activeTab: "all" // "all", "green", "orange", "red"
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

  readonly property var visibleHosts: {
    var list = root.netscanData && root.netscanData.hosts ? root.netscanData.hosts : []
    if (root.activeTab === "all") return list
    if (root.activeTab === "green") {
      return list.filter(function(h) {
        if (h.isRepeater) return (h.downstreamHosts || []).some(function(d) { return d.category === "green" })
        return h.category === "green"
      })
    }
    if (root.activeTab === "orange") {
      return list.filter(function(h) {
        if (h.isRepeater) return true
        return h.category === "orange"
      })
    }
    if (root.activeTab === "red") {
      return list.filter(function(h) {
        if (h.isRepeater) return (h.downstreamHosts || []).some(function(d) { return d.category === "red" })
        return h.category === "red" || (h.warnings && h.warnings.length > 0)
      })
    }
    return list
  }

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
    contentWidth: panel.fittedContentWidth(Style.space(600))
    contentHeight: panel.fittedContentHeight(mainColumn.implicitHeight + Style.space(32), Style.space(720))

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
        else if (t === "1") { root.activeTab = "all"; root.selectedIndex = 0 }
        else if (t === "2") { root.activeTab = "green"; root.selectedIndex = 0 }
        else if (t === "3") { root.activeTab = "orange"; root.selectedIndex = 0 }
        else if (t === "4") { root.activeTab = "red"; root.selectedIndex = 0 }
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
        id: scrollArea
        anchors.fill: parent
        contentWidth: mainColumn.width
        contentHeight: mainColumn.implicitHeight + Style.space(24)
        clip: true
        boundsBehavior: Flickable.StopAtBounds

        Column {
          id: mainColumn
          width: scrollArea.width
          spacing: Style.space(10)
          topPadding: Style.space(12)
          bottomPadding: Style.space(12)
          leftPadding: Style.space(14)
          rightPadding: Style.space(14)

          // --- HEADER: TITLE & CONTROLS ---
          Item {
            width: parent.width - Style.space(28)
            implicitHeight: Style.space(42)

            Row {
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(10)

              Text {
                textFormat: Text.PlainText
                text: "󰛳"
                font.family: root.contentFontFamily
                font.pixelSize: Style.font.title
                color: Color.accent
                anchors.verticalCenter: parent.verticalCenter
              }

              Column {
                anchors.verticalCenter: parent.verticalCenter
                spacing: 2

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
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              implicitWidth: Style.space(114)
              implicitHeight: Style.space(32)
              radius: Style.cornerRadius
              color: rescanMouse.containsMouse ? Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.2) : Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.1)
              borderSpec: Border.controlSpec("normal", Color.accent, Color.accent)

              Row {
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

          // --- CATEGORY TABS (ALL / GREEN / ORANGE / RED) ---
          Row {
            width: parent.width - Style.space(28)
            spacing: Style.space(6)

            // Tab 1: All
            BorderSurface {
              id: tabAll
              readonly property bool isSelected: root.activeTab === "all"
              width: (parent.width - Style.space(18)) / 4
              implicitHeight: Style.space(30)
              radius: Style.cornerRadius
              color: tabAll.isSelected ? Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.2) : Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.03)
              borderSpec: Border.controlSpec("normal", tabAll.isSelected ? Color.accent : Qt.darker(root.contentForeground, 3.5), Color.accent)

              Row {
                anchors.centerIn: parent
                spacing: Style.space(4)
                Text { textFormat: Text.PlainText; text: "󰒋"; font.pixelSize: Style.font.caption; color: tabAll.isSelected ? Color.accent : root.contentSubtle }
                Text { textFormat: Text.PlainText; text: "All (" + (root.netscanData.totalHosts || 0) + ")"; font.family: root.contentFontFamily; font.pixelSize: 11; font.bold: tabAll.isSelected; color: tabAll.isSelected ? Color.accent : root.contentForeground }
              }
              MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: { root.activeTab = "all"; root.selectedIndex = 0 } }
            }

            // Tab 2: Green (Verified / Active)
            BorderSurface {
              id: tabGreen
              readonly property bool isSelected: root.activeTab === "green"
              width: (parent.width - Style.space(18)) / 4
              implicitHeight: Style.space(30)
              radius: Style.cornerRadius
              color: tabGreen.isSelected ? Qt.rgba(0.06, 0.72, 0.51, 0.2) : Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.03)
              borderSpec: Border.controlSpec("normal", tabGreen.isSelected ? "#10b981" : Qt.darker(root.contentForeground, 3.5), "#10b981")

              Row {
                anchors.centerIn: parent
                spacing: Style.space(4)
                Text { textFormat: Text.PlainText; text: "󰄲"; font.pixelSize: Style.font.caption; color: "#10b981" }
                Text { textFormat: Text.PlainText; text: "Active (" + (root.netscanData.greenCount || 0) + ")"; font.family: root.contentFontFamily; font.pixelSize: 11; font.bold: tabGreen.isSelected; color: tabGreen.isSelected ? "#10b981" : root.contentForeground }
              }
              MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: { root.activeTab = "green"; root.selectedIndex = 0 } }
            }

            // Tab 3: Orange (AP & Idle)
            BorderSurface {
              id: tabOrange
              readonly property bool isSelected: root.activeTab === "orange"
              width: (parent.width - Style.space(18)) / 4
              implicitHeight: Style.space(30)
              radius: Style.cornerRadius
              color: tabOrange.isSelected ? Qt.rgba(0.96, 0.62, 0.04, 0.2) : Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.03)
              borderSpec: Border.controlSpec("normal", tabOrange.isSelected ? "#f59e0b" : Qt.darker(root.contentForeground, 3.5), "#f59e0b")

              Row {
                anchors.centerIn: parent
                spacing: Style.space(4)
                Text { textFormat: Text.PlainText; text: "󰀝"; font.pixelSize: Style.font.caption; color: "#f59e0b" }
                Text { textFormat: Text.PlainText; text: "AP/Idle (" + (root.netscanData.orangeCount || 0) + ")"; font.family: root.contentFontFamily; font.pixelSize: 11; font.bold: tabOrange.isSelected; color: tabOrange.isSelected ? "#f59e0b" : root.contentForeground }
              }
              MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: { root.activeTab = "orange"; root.selectedIndex = 0 } }
            }

            // Tab 4: Red (Security Alerts)
            BorderSurface {
              id: tabRed
              readonly property bool isSelected: root.activeTab === "red"
              width: (parent.width - Style.space(18)) / 4
              implicitHeight: Style.space(30)
              radius: Style.cornerRadius
              color: tabRed.isSelected ? Qt.rgba(0.94, 0.27, 0.27, 0.2) : Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.03)
              borderSpec: Border.controlSpec("normal", tabRed.isSelected ? "#ef4444" : Qt.darker(root.contentForeground, 3.5), "#ef4444")

              Row {
                anchors.centerIn: parent
                spacing: Style.space(4)
                Text { textFormat: Text.PlainText; text: "󰚌"; font.pixelSize: Style.font.caption; color: "#ef4444" }
                Text { textFormat: Text.PlainText; text: "Notices (" + (root.netscanData.securityWarningsCount || 0) + ")"; font.family: root.contentFontFamily; font.pixelSize: 11; font.bold: tabRed.isSelected; color: tabRed.isSelected ? "#ef4444" : root.contentForeground }
              }
              MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: { root.activeTab = "red"; root.selectedIndex = 0 } }
            }
          }

          // --- DEVICE LIST ---
          Repeater {
            model: root.visibleHosts
            delegate: Column {
              id: hostDelegate
              required property var modelData
              required property int index
              readonly property bool isSelected: root.selectedIndex === index
              readonly property bool isRepeater: !!modelData.isRepeater
              readonly property bool isExpanded: isRepeater && !!root.expandedRepeaters[modelData.mac]

              width: mainColumn.width - Style.space(28)
              spacing: Style.space(4)

              // Main Host or Repeater Header Card
              BorderSurface {
                width: parent.width
                implicitHeight: hostCol.implicitHeight + Style.space(18)
                radius: Style.cornerRadius
                color: isSelected
                  ? Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.16)
                  : (hostMouse.containsMouse ? Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.06) : Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.02))
                borderSpec: Border.controlSpec(
                  modelData.category === "red" ? "error" : (isSelected ? "focus" : "normal"),
                  modelData.category === "red" ? "#ef4444" : (modelData.category === "green" ? "#10b981" : (isSelected ? Color.accent : Qt.darker(root.contentForeground, 2.5))),
                  Color.accent
                )

                Column {
                  id: hostCol
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.top: parent.top
                  anchors.margins: Style.space(10)
                  spacing: Style.space(6)

                  // Line 1: Type Icon, Device Name, IP & Badges
                  Item {
                    width: parent.width
                    implicitHeight: Style.space(22)

                    Row {
                      anchors.left: parent.left
                      anchors.verticalCenter: parent.verticalCenter
                      spacing: Style.space(8)

                      Text {
                        textFormat: Text.PlainText
                        text: modelData.typeIcon || "󰖩"
                        font.family: root.contentFontFamily
                        font.pixelSize: Style.font.body
                        color: isRepeater ? "#f59e0b" : (modelData.isSelf ? "#10b981" : (modelData.isGateway ? "#3b82f6" : (modelData.category === "green" ? "#10b981" : Color.accent)))
                        anchors.verticalCenter: parent.verticalCenter
                      }

                      // Primary Title: Friendly Name or IP
                      Text {
                        textFormat: Text.PlainText
                        text: isRepeater
                          ? modelData.summary
                          : (modelData.friendlyName || modelData.ip)
                        font.family: root.contentFontFamily
                        font.pixelSize: Style.font.bodySmall
                        font.bold: true
                        color: root.contentForeground
                        anchors.verticalCenter: parent.verticalCenter
                      }

                      // Secondary IP display if friendly name exists
                      Text {
                        visible: !isRepeater && !!modelData.friendlyName && modelData.friendlyName !== modelData.ip
                        textFormat: Text.PlainText
                        text: "(" + modelData.ip + ")"
                        font.family: "Monospace"
                        font.pixelSize: 11
                        color: root.contentSubtle
                        anchors.verticalCenter: parent.verticalCenter
                      }

                      // Role Badge
                      Rectangle {
                        height: Style.space(18)
                        implicitWidth: roleText.implicitWidth + Style.space(10)
                        radius: 4
                        color: isRepeater
                          ? Qt.rgba(0.96, 0.62, 0.04, 0.2)
                          : (modelData.isSelf
                              ? Qt.rgba(0.06, 0.72, 0.51, 0.2)
                              : (modelData.isGateway
                                  ? Qt.rgba(0.23, 0.51, 0.96, 0.2)
                                  : (modelData.category === "green" ? Qt.rgba(0.06, 0.72, 0.51, 0.16) : Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.2))))
                        anchors.verticalCenter: parent.verticalCenter

                        Text {
                          id: roleText
                          anchors.centerIn: parent
                          textFormat: Text.PlainText
                          text: isRepeater ? "COLLAPSED AP" : (modelData.guessedType || "Generic")
                          font.family: root.contentFontFamily
                          font.pixelSize: 11
                          font.bold: true
                          color: isRepeater ? "#f59e0b" : (modelData.isSelf ? "#10b981" : (modelData.isGateway ? "#60a5fa" : (modelData.category === "green" ? "#10b981" : Color.accent)))
                        }
                      }
                    }

                    // Accordion arrow for Repeater
                    Text {
                      visible: isRepeater
                      anchors.right: parent.right
                      anchors.verticalCenter: parent.verticalCenter
                      textFormat: Text.PlainText
                      text: isExpanded ? "󰅃 Collapse (e)" : "󰅀 Expand (e)"
                      font.family: root.contentFontFamily
                      font.pixelSize: Style.font.caption
                      font.bold: true
                      color: "#f59e0b"
                    }
                  }

                  // Line 2: Vendor, MAC, Latency, Open Ports
                  Item {
                    width: parent.width
                    implicitHeight: Style.space(18)

                    Row {
                      anchors.left: parent.left
                      anchors.verticalCenter: parent.verticalCenter
                      spacing: Style.space(14)

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

                      Text {
                        visible: !isRepeater && modelData.latencyMs !== null && modelData.latencyMs !== undefined
                        textFormat: Text.PlainText
                        text: "· " + modelData.latencyMs + "ms"
                        font.family: root.contentFontFamily
                        font.pixelSize: 11
                        color: "#10b981"
                      }
                    }

                    // Open Ports tags with service names
                    Row {
                      anchors.right: parent.right
                      anchors.verticalCenter: parent.verticalCenter
                      spacing: 4
                      visible: !isRepeater && modelData.portLabels && modelData.portLabels.length > 0
                      Repeater {
                        model: (modelData.portLabels || []).slice(0, 4)
                        delegate: Rectangle {
                          height: 16
                          implicitWidth: portText.implicitWidth + 8
                          radius: 3
                          color: (modelData.indexOf("Insecure") !== -1 || modelData.indexOf("Telnet") !== -1 || modelData.indexOf("Docker API") !== -1)
                            ? Qt.rgba(0.94, 0.27, 0.27, 0.2)
                            : (modelData.indexOf("SMB") !== -1 || modelData.indexOf("FTP") !== -1 || modelData.indexOf("RDP") !== -1
                                ? Qt.rgba(0.96, 0.62, 0.04, 0.2)
                                : Qt.rgba(0.06, 0.72, 0.51, 0.16))
                          Text {
                            id: portText
                            anchors.centerIn: parent
                            textFormat: Text.PlainText
                            text: String(modelData)
                            font.family: "Monospace"
                            font.pixelSize: 10
                            color: (modelData.indexOf("Insecure") !== -1 || modelData.indexOf("Telnet") !== -1 || modelData.indexOf("Docker API") !== -1)
                              ? "#ef4444"
                              : (modelData.indexOf("SMB") !== -1 || modelData.indexOf("FTP") !== -1 || modelData.indexOf("RDP") !== -1
                                  ? "#f59e0b"
                                  : "#10b981")
                          }
                        }
                      }
                    }
                  }

                  // Security Warnings Row (if any active vulnerabilities / exposures)
                  Row {
                    visible: !isRepeater && modelData.warnings && modelData.warnings.length > 0
                    spacing: 6
                    Repeater {
                      model: modelData.warnings || []
                      delegate: Rectangle {
                        height: 18
                        implicitWidth: warnText.implicitWidth + 12
                        radius: 3
                        color: modelData.severity === "critical"
                          ? Qt.rgba(0.94, 0.27, 0.27, 0.15)
                          : (modelData.severity === "warning"
                              ? Qt.rgba(0.96, 0.62, 0.04, 0.15)
                              : Qt.rgba(0.23, 0.51, 0.96, 0.15))
                        border.color: modelData.severity === "critical" ? "#ef4444" : (modelData.severity === "warning" ? "#f59e0b" : "#3b82f6")
                        border.width: 1

                        Row {
                          anchors.centerIn: parent
                          spacing: 4
                          Text {
                            textFormat: Text.PlainText
                            text: modelData.severity === "critical" ? "󰚌" : (modelData.severity === "warning" ? "󰌵" : "󰋼")
                            font.family: root.contentFontFamily
                            font.pixelSize: 10
                            color: modelData.severity === "critical" ? "#ef4444" : (modelData.severity === "warning" ? "#f59e0b" : "#3b82f6")
                          }
                          Text {
                            id: warnText
                            textFormat: Text.PlainText
                            text: modelData.text
                            font.family: root.contentFontFamily
                            font.pixelSize: 10
                            font.bold: true
                            color: modelData.severity === "critical" ? "#ef4444" : (modelData.severity === "warning" ? "#f59e0b" : "#60a5fa")
                          }
                        }
                      }
                    }
                  }

                  // Deep scan inline result
                  BorderSurface {
                    visible: !isRepeater && !!root.deepScanResults[modelData.ip]
                    width: parent.width
                    implicitHeight: deepScanResultCol.implicitHeight + 14
                    radius: 4
                    color: "#181825"
                    borderSpec: Border.controlSpec("normal", "#313244", "#89b4fa")

                    Column {
                      id: deepScanResultCol
                      anchors.left: parent.left
                      anchors.right: parent.right
                      anchors.top: parent.top
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
              Column {
                visible: isExpanded
                width: parent.width
                leftPadding: Style.space(16)
                spacing: Style.space(6)

                Repeater {
                  model: {
                    var items = modelData.downstreamHosts || []
                    if (root.activeTab === "green") return items.filter(function(d) { return d.category === "green" })
                    if (root.activeTab === "orange") return items.filter(function(d) { return d.category === "orange" })
                    if (root.activeTab === "red") return items.filter(function(d) { return d.category === "red" })
                    return items
                  }
                  delegate: BorderSurface {
                    required property var modelData
                    width: parent.width - Style.space(16)
                    implicitHeight: downCardCol.implicitHeight + Style.space(16)
                    radius: 4
                    color: (modelData.openPorts && modelData.openPorts.length > 0)
                      ? Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.08)
                      : (downMouse.containsMouse ? Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.08) : Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.03))
                    borderSpec: Border.controlSpec("normal", (modelData.openPorts && modelData.openPorts.length > 0) ? (modelData.category === "green" ? "#10b981" : Color.accent) : Qt.darker(root.contentForeground, 3.5), Color.accent)

                    Column {
                      id: downCardCol
                      anchors.left: parent.left
                      anchors.right: parent.right
                      anchors.top: parent.top
                      anchors.margins: Style.space(8)
                      spacing: Style.space(4)

                      // Line 1: Icon, Friendly Name, IP, Role Badge, Copy Action
                      Item {
                        width: parent.width
                        implicitHeight: Style.space(20)

                        Row {
                          anchors.left: parent.left
                          anchors.verticalCenter: parent.verticalCenter
                          spacing: Style.space(8)

                          Text {
                            textFormat: Text.PlainText
                            text: modelData.typeIcon || "󰖩"
                            font.family: root.contentFontFamily
                            font.pixelSize: Style.font.bodySmall
                            color: (modelData.category === "green" ? "#10b981" : ((modelData.openPorts && modelData.openPorts.length > 0) ? Color.accent : "#f59e0b"))
                            anchors.verticalCenter: parent.verticalCenter
                          }

                          Text {
                            textFormat: Text.PlainText
                            text: modelData.friendlyName || modelData.ip
                            font.family: root.contentFontFamily
                            font.pixelSize: Style.font.caption
                            font.bold: true
                            color: root.contentForeground
                            anchors.verticalCenter: parent.verticalCenter
                          }

                          Text {
                            visible: !!modelData.friendlyName && modelData.friendlyName !== modelData.ip
                            textFormat: Text.PlainText
                            text: "(" + modelData.ip + ")"
                            font.family: "Monospace"
                            font.pixelSize: 10
                            color: root.contentSubtle
                            anchors.verticalCenter: parent.verticalCenter
                          }

                          // Role badge for active downstream hosts (e.g. Dokploy, Proxmox, Ubuntu)
                          Rectangle {
                            visible: modelData.guessedType !== "Generic Host"
                            height: 16
                            implicitWidth: downRoleText.implicitWidth + 8
                            radius: 3
                            color: modelData.category === "green" ? Qt.rgba(0.06, 0.72, 0.51, 0.2) : Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.2)
                            anchors.verticalCenter: parent.verticalCenter
                            Text {
                              id: downRoleText
                              anchors.centerIn: parent
                              textFormat: Text.PlainText
                              text: modelData.guessedType || ""
                              font.family: root.contentFontFamily
                              font.pixelSize: 9
                              font.bold: true
                              color: modelData.category === "green" ? "#10b981" : Color.accent
                            }
                          }
                        }

                        Text {
                          anchors.right: parent.right
                          anchors.verticalCenter: parent.verticalCenter
                          textFormat: Text.PlainText
                          text: "󰆏 Copy"
                          font.family: root.contentFontFamily
                          font.pixelSize: 11
                          font.bold: true
                          color: Color.accent
                        }
                      }

                      // Line 2: Open Ports on downstream host (if any)
                      Row {
                        visible: modelData.portLabels && modelData.portLabels.length > 0
                        spacing: 4
                        Repeater {
                          model: (modelData.portLabels || []).slice(0, 5)
                          delegate: Rectangle {
                            height: 16
                            implicitWidth: downPortText.implicitWidth + 8
                            radius: 3
                            color: (modelData.indexOf("Dokploy") !== -1 || modelData.indexOf("Jellyfin") !== -1 || modelData.indexOf("Proxmox") !== -1)
                              ? Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.2)
                              : Qt.rgba(0.06, 0.72, 0.51, 0.16)
                            Text {
                              id: downPortText
                              anchors.centerIn: parent
                              textFormat: Text.PlainText
                              text: String(modelData)
                              font.family: "Monospace"
                              font.pixelSize: 9
                              color: (modelData.indexOf("Dokploy") !== -1 || modelData.indexOf("Jellyfin") !== -1 || modelData.indexOf("Proxmox") !== -1)
                                ? Color.accent
                                : "#10b981"
                            }
                          }
                        }
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

          // --- FOOTER SHORTCUTS (CLEAN 2-ROW GRID WITHOUT OVERFLOW) ---
          BorderSurface {
            width: parent.width - Style.space(28)
            implicitHeight: Style.space(56)
            radius: Style.cornerRadius
            color: Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.02)
            borderSpec: Border.controlSpec("normal", Qt.darker(root.contentForeground, 3.0), Color.accent)

            Column {
              anchors.centerIn: parent
              spacing: Style.space(4)

              Row {
                anchors.horizontalCenter: parent.horizontalCenter
                spacing: Style.space(12)

                // Shortcut 1
                Row {
                  spacing: 4
                  Rectangle { height: 16; width: 16; radius: 3; color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.2); Text { anchors.centerIn: parent; text: "r"; font.pixelSize: 10; font.bold: true; color: Color.accent } }
                  Text { textFormat: Text.PlainText; text: "Rescan"; font.family: root.contentFontFamily; font.pixelSize: 11; color: root.contentSubtle }
                }
                // Shortcut 2
                Row {
                  spacing: 4
                  Rectangle { height: 16; width: 22; radius: 3; color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.2); Text { anchors.centerIn: parent; text: "1-4"; font.pixelSize: 10; font.bold: true; color: Color.accent } }
                  Text { textFormat: Text.PlainText; text: "Tabs"; font.family: root.contentFontFamily; font.pixelSize: 11; color: root.contentSubtle }
                }
                // Shortcut 3
                Row {
                  spacing: 4
                  Rectangle { height: 16; width: 16; radius: 3; color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.2); Text { anchors.centerIn: parent; text: "d"; font.pixelSize: 10; font.bold: true; color: Color.accent } }
                  Text { textFormat: Text.PlainText; text: "Deep Scan"; font.family: root.contentFontFamily; font.pixelSize: 11; color: root.contentSubtle }
                }
                // Shortcut 4
                Row {
                  spacing: 4
                  Rectangle { height: 16; width: 16; radius: 3; color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.2); Text { anchors.centerIn: parent; text: "c"; font.pixelSize: 10; font.bold: true; color: Color.accent } }
                  Text { textFormat: Text.PlainText; text: "Copy IP"; font.family: root.contentFontFamily; font.pixelSize: 11; color: root.contentSubtle }
                }
              }

              Row {
                anchors.horizontalCenter: parent.horizontalCenter
                spacing: Style.space(12)

                // Shortcut 5
                Row {
                  spacing: 4
                  Rectangle { height: 16; width: 16; radius: 3; color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.2); Text { anchors.centerIn: parent; text: "m"; font.pixelSize: 10; font.bold: true; color: Color.accent } }
                  Text { textFormat: Text.PlainText; text: "Copy MAC"; font.family: root.contentFontFamily; font.pixelSize: 11; color: root.contentSubtle }
                }
                // Shortcut 6
                Row {
                  spacing: 4
                  Rectangle { height: 16; width: 16; radius: 3; color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.2); Text { anchors.centerIn: parent; text: "e"; font.pixelSize: 10; font.bold: true; color: Color.accent } }
                  Text { textFormat: Text.PlainText; text: "Toggle AP"; font.family: root.contentFontFamily; font.pixelSize: 11; color: root.contentSubtle }
                }
                // Shortcut 7
                Row {
                  spacing: 4
                  Rectangle { height: 16; implicitWidth: 26; radius: 3; color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.2); Text { anchors.centerIn: parent; text: "Esc"; font.pixelSize: 10; font.bold: true; color: Color.accent } }
                  Text { textFormat: Text.PlainText; text: "Close"; font.family: root.contentFontFamily; font.pixelSize: 11; color: root.contentSubtle }
                }
              }
            }
          }
        }
      }
    }
  }
}
