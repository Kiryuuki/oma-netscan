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
  property var settings: null
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
  property int selectedIntervalMin: (settings && settings.refreshIntervalMin) ? settings.refreshIntervalMin : 15

  function open() { root.controller.show() }
  function close() { root.controller.hide() }
  function toggle() { if (root.opened) close(); else open(); }
  function refresh() {
    if (hostWidget && hostWidget.refresh) hostWidget.refresh()
  }

  function setIntervalMin(m) {
    root.selectedIntervalMin = m
    if (root.settings) root.settings.refreshIntervalMin = m
    if (hostWidget && hostWidget.autoScanTimer) {
      hostWidget.autoScanTimer.interval = m * 60 * 1000
    }
    root.copyNotice = "Refresh set to " + m + "m"
    noticeTimer.restart()
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

    readonly property var categoryCounts: {
    var list = root.netscanData && root.netscanData.hosts ? root.netscanData.hosts : []
    var all = list.length
    var servers = 0
    var lxc = 0
    var apps = 0
    var clients = 0
    var security = 0
    
    for (var i = 0; i < list.length; i++) {
      var h = list[i]
      var gt = (h.guessedType || "").toLowerCase()
      var ports = h.openPorts || []
      var hasWarn = (h.warnings && h.warnings.length > 0) || h.category === "red"
      
      if (hasWarn) security++
      if (gt.indexOf("proxmox") !== -1 || gt.indexOf("hypervisor") !== -1 || gt.indexOf("gateway") !== -1 || gt.indexOf("router") !== -1 || gt.indexOf("dns") !== -1) {
        servers++
      }
      if (gt.indexOf("lxc") !== -1 || gt.indexOf("ubuntu") !== -1 || gt.indexOf("debian") !== -1 || gt.indexOf("container") !== -1 || gt.indexOf("docker") !== -1) {
        lxc++
      }
      if (ports.some(function(p) { return [80, 443, 3000, 3001, 5000, 5055, 5173, 7878, 8006, 8080, 8096, 8123, 8443, 8989, 9000, 9443, 37575].indexOf(p) !== -1 })) {
        apps++
      }
      if (gt.indexOf("workstation") !== -1 || gt.indexOf("host (ssh)") !== -1 || gt.indexOf("phone") !== -1 || gt.indexOf("mobile") !== -1 || gt.indexOf("apple") !== -1 || gt.indexOf("tv") !== -1 || gt.indexOf("camera") !== -1 || gt.indexOf("generic") !== -1 || gt.indexOf("repeater") !== -1) {
        clients++
      }
    }
    return { all: all, servers: servers, lxc: lxc, apps: apps, clients: clients, security: security }
  }

  readonly property var visibleHosts: {
    var list = root.netscanData && root.netscanData.hosts ? root.netscanData.hosts : []
    if (root.activeTab === "all") return list
    if (root.activeTab === "servers") {
      return list.filter(function(h) {
        var gt = (h.guessedType || "").toLowerCase()
        return gt.indexOf("proxmox") !== -1 || gt.indexOf("hypervisor") !== -1 || gt.indexOf("gateway") !== -1 || gt.indexOf("router") !== -1 || gt.indexOf("dns") !== -1
      })
    }
    if (root.activeTab === "lxc") {
      return list.filter(function(h) {
        var gt = (h.guessedType || "").toLowerCase()
        return gt.indexOf("lxc") !== -1 || gt.indexOf("ubuntu") !== -1 || gt.indexOf("debian") !== -1 || gt.indexOf("container") !== -1 || gt.indexOf("docker") !== -1
      })
    }
    if (root.activeTab === "apps") {
      return list.filter(function(h) {
        var ports = h.openPorts || []
        return ports.some(function(p) { return [80, 443, 3000, 3001, 5000, 5055, 5173, 7878, 8006, 8080, 8096, 8123, 8443, 8989, 9000, 9443, 37575].indexOf(p) !== -1 })
      })
    }
    if (root.activeTab === "clients") {
      return list.filter(function(h) {
        var gt = (h.guessedType || "").toLowerCase()
        return gt.indexOf("workstation") !== -1 || gt.indexOf("host (ssh)") !== -1 || gt.indexOf("phone") !== -1 || gt.indexOf("mobile") !== -1 || gt.indexOf("apple") !== -1 || gt.indexOf("tv") !== -1 || gt.indexOf("camera") !== -1 || gt.indexOf("generic") !== -1 || gt.indexOf("repeater") !== -1
      })
    }
    if (root.activeTab === "security") {
      return list.filter(function(h) {
        if (h.isRepeater) return (h.downstreamHosts || []).some(function(d) { return d.category === "red" || (d.warnings && d.warnings.length > 0) })
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
    contentWidth: panel.fittedContentWidth(Style.space(640))
    contentHeight: panel.fittedContentHeight(mainColumn.implicitHeight + Style.space(32), Style.space(760))

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
        else if (t === "2") { root.activeTab = "servers"; root.selectedIndex = 0 }
        else if (t === "3") { root.activeTab = "lxc"; root.selectedIndex = 0 }
        else if (t === "4") { root.activeTab = "apps"; root.selectedIndex = 0 }
        else if (t === "5") { root.activeTab = "clients"; root.selectedIndex = 0 }
        else if (t === "6") { root.activeTab = "security"; root.selectedIndex = 0 }
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
                  text: "LOCAL NETWORK RECON & AUDIT"
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

            // Top Right Cluster: "Updated 0m ago" beside [Rescan (r)] Button
            Row {
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(10)

              Text {
                textFormat: Text.PlainText
                text: root.copyNotice ? root.copyNotice : ("Updated " + (root.netscanData.updatedAt ? Math.round((Date.now()/1000 - root.netscanData.updatedAt)/60) + "m ago" : "just now"))
                font.family: root.contentFontFamily
                font.pixelSize: 11
                color: root.copyNotice ? Color.accent : root.contentSubtle
                anchors.verticalCenter: parent.verticalCenter
              }

              BorderSurface {
                id: rescanBtn
                implicitWidth: Style.space(110)
                implicitHeight: Style.space(32)
                radius: Style.cornerRadius
                color: rescanMouse.pressed
                  ? Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.35)
                  : (rescanMouse.containsMouse || root.isScanning
                      ? Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.2)
                      : Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.1))
                borderSpec: Border.controlSpec("normal", Color.accent, Color.accent)

                Row {
                  anchors.centerIn: parent
                  spacing: Style.space(6)
                  Text {
                    id: rescanIcon
                    textFormat: Text.PlainText
                    text: "󰑐"
                    font.family: root.contentFontFamily
                    font.pixelSize: Style.font.caption
                    color: Color.accent
                    rotation: root.isScanning ? spinAnim.angle : 0

                    NumberAnimation on rotation {
                      id: spinAnim
                      property real angle: 0
                      running: root.isScanning
                      loops: Animation.Infinite
                      from: 0
                      to: 360
                      duration: 900
                    }
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
                  onClicked: {
                    root.isScanning = true
                    root.copyNotice = "Scanning..."
                    noticeTimer.restart()
                    root.refresh()
                  }
                }
              }
            }
          }

          // --- REFRESH RATE CONTROLS ROW (1m, 15m, 60m, Custom) ---
          Row {
            width: parent.width - Style.space(28)
            spacing: Style.space(6)

            Text {
              textFormat: Text.PlainText
              text: "Auto-scan:"
              font.family: root.contentFontFamily
              font.pixelSize: 11
              color: root.contentSubtle
              anchors.verticalCenter: parent.verticalCenter
            }

            Repeater {
              model: [
                { label: "1m", value: 1 },
                { label: "5m", value: 5 },
                { label: "15m", value: 15 },
                { label: "60m", value: 60 }
              ]
              delegate: BorderSurface {
                required property var modelData
                readonly property bool isSelected: root.selectedIntervalMin === modelData.value
                width: Style.space(42)
                implicitHeight: Style.space(22)
                radius: 4
                color: isSelected ? Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.25) : Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.04)
                borderSpec: Border.controlSpec("normal", isSelected ? Color.accent : Qt.darker(root.contentForeground, 3.5), Color.accent)

                Text {
                  anchors.centerIn: parent
                  textFormat: Text.PlainText
                  text: modelData.label
                  font.family: "Monospace"
                  font.pixelSize: 10
                  font.bold: isSelected
                  color: isSelected ? Color.accent : root.contentSubtle
                }

                MouseArea {
                  anchors.fill: parent
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.setIntervalMin(modelData.value)
                }
              }
            }

            Text {
              textFormat: Text.PlainText
              text: "· Lightweight liveness checks (0% CPU / <2KB)"
              font.family: root.contentFontFamily
              font.pixelSize: 10
              color: root.contentSubtle
              anchors.verticalCenter: parent.verticalCenter
            }
          }

          // --- CATEGORY & DEVICE FILTER TABS ---
          RowLayout {
            width: parent.width - Style.space(28)
            spacing: Style.space(4)

            Repeater {
              model: [
                { key: "all", label: "All (" + root.categoryCounts.all + ")", icon: "󰒋", color: Color.accent },
                { key: "servers", label: "Nodes (" + root.categoryCounts.servers + ")", icon: "󰒋", color: "#10b981" },
                { key: "lxc", label: "LXC/OS (" + root.categoryCounts.lxc + ")", icon: "󰣚", color: "#06b6d4" },
                { key: "apps", label: "Exposed (" + root.categoryCounts.apps + ")", icon: "󰖟", color: "#8b5cf6" },
                { key: "clients", label: "Clients (" + root.categoryCounts.clients + ")", icon: "󰌢", color: "#f59e0b" },
                { key: "security", label: "Audits (" + root.categoryCounts.security + ")", icon: "󰅖", color: "#ef4444" }
              ]

              delegate: BorderSurface {
                id: cTabBtn
                required property var modelData
                readonly property bool isSelected: root.activeTab === modelData.key

                Layout.fillWidth: true
                implicitHeight: Style.space(30)
                radius: Style.cornerRadius
                color: isSelected ? Qt.rgba(modelData.color.r, modelData.color.g, modelData.color.b, 0.22) : (cTabHover.hovered ? Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.08) : Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.03))
                borderSpec: Border.controlSpec(isSelected ? "focus" : "normal", isSelected ? modelData.color : Qt.darker(root.contentForeground, 3.5), modelData.color)

                HoverHandler { id: cTabHover }

                Row {
                  anchors.centerIn: parent
                  spacing: Style.space(3)

                  Text {
                    textFormat: Text.PlainText
                    text: cTabBtn.modelData.icon
                    font.family: root.contentFontFamily
                    font.pixelSize: Style.font.caption
                    color: cTabBtn.isSelected ? cTabBtn.modelData.color : root.contentSubtle
                  }

                  Text {
                    textFormat: Text.PlainText
                    text: cTabBtn.modelData.label
                    font.family: root.contentFontFamily
                    font.pixelSize: 10
                    font.bold: cTabBtn.isSelected
                    color: cTabBtn.isSelected ? cTabBtn.modelData.color : root.contentForeground
                  }
                }

                MouseArea {
                  anchors.fill: parent
                  cursorShape: Qt.PointingHandCursor
                  onClicked: {
                    root.activeTab = cTabBtn.modelData.key
                    root.selectedIndex = 0
                  }
                }
              }
            }
          }

          // --- MULTI-LINE FULL MESSAGE HOMELAB AUDIT BANNER (ZERO OVERLAP) ---
          BorderSurface {
            width: parent.width - Style.space(28)
            implicitHeight: bannerCol.implicitHeight + Style.space(16)
            radius: Style.cornerRadius
            color: root.activeTab === "red"
              ? Qt.rgba(0.94, 0.27, 0.27, 0.1)
              : (root.activeTab === "orange"
                  ? Qt.rgba(0.96, 0.62, 0.04, 0.1)
                  : (root.activeTab === "green" ? Qt.rgba(0.06, 0.72, 0.51, 0.1) : Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.04)))
            borderSpec: Border.controlSpec("normal",
              root.activeTab === "red" ? "#ef4444" : (root.activeTab === "orange" ? "#f59e0b" : (root.activeTab === "green" ? "#10b981" : Qt.darker(root.contentForeground, 3.0))),
              Color.accent
            )

            Column {
              id: bannerCol
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.top: parent.top
              anchors.margins: Style.space(8)
              spacing: 2

              Row {
                spacing: Style.space(6)
                Text {
                  textFormat: Text.PlainText
                  text: root.activeTab === "red" ? "󰚌" : (root.activeTab === "orange" ? "󰀝" : (root.activeTab === "green" ? "󰄲" : "󰛳"))
                  font.family: root.contentFontFamily
                  font.pixelSize: 11
                  color: root.activeTab === "red" ? "#ef4444" : (root.activeTab === "orange" ? "#f59e0b" : (root.activeTab === "green" ? "#10b981" : Color.accent))
                }
                Text {
                  textFormat: Text.PlainText
                  text: root.activeTab === "red"
                    ? "Critical Security Risks Audit"
                    : (root.activeTab === "orange"
                        ? "Attention & Exposure Review"
                        : (root.activeTab === "green"
                            ? "Verified Network Services Verified Homelab Services & Clusters Hosts"
                            : "Subnet Reconnaissance & Inventory"))
                  font.family: root.contentFontFamily
                  font.pixelSize: 11
                  font.bold: true
                  color: root.activeTab === "red" ? "#ef4444" : (root.activeTab === "orange" ? "#f59e0b" : (root.activeTab === "green" ? "#10b981" : root.contentForeground))
                }
              }

              Text {
                textFormat: Text.PlainText
                text: root.activeTab === "red"
                  ? "Hosts with insecure remote protocols (Telnet 23, plaintext FTP 21, unauthenticated Docker daemon API 2375). Actionable remediation recommended."
                  : (root.activeTab === "orange"
                      ? "Hosts requiring attention: unencrypted HTTP admin interfaces (port 80 without SSL), active SMB/RTSP streams, or idle unfingerprinted clients."
                      : (root.activeTab === "green"
                          ? "Healthy network infrastructure: Proxmox VE hypervisors, Dokploy container platforms, KASM workspaces, Ubuntu/Debian LXCs, and active DNS resolvers."
                          : (root.netscanData.totalHosts || 0) + " total devices detected across " + root.netscanData.subnet + ". Click any host to copy IP or press [d] for deep scan."))
                font.family: root.contentFontFamily
                font.pixelSize: 10
                color: root.contentSubtle
                wrapMode: Text.WordWrap
                width: parent.width
              }
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
                implicitHeight: hostCol.implicitHeight + Style.space(20)
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

                  // Line 1: Type Icon, Device Name, IP in parens, Role Badge, Copy Action
                  Item {
                    width: parent.width
                    implicitHeight: Style.space(22)

                    Row {
                      anchors.left: parent.left
                      anchors.right: actionText.left
                      anchors.rightMargin: Style.space(8)
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
                        elide: Text.ElideRight
                      }

                      // Secondary IP display if friendly name exists and is distinct from IP
                      Text {
                        visible: !isRepeater && !!modelData.friendlyName && modelData.friendlyName !== modelData.ip && modelData.friendlyName.indexOf(modelData.ip) === -1
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

                    // Accordion arrow for Repeater / Copy for host
                    Text {
                      id: actionText
                      anchors.right: parent.right
                      anchors.verticalCenter: parent.verticalCenter
                      textFormat: Text.PlainText
                      text: isRepeater ? (isExpanded ? "󰅃 Collapse (e)" : "󰅀 Expand (e)") : "󰆏 Copy"
                      font.family: root.contentFontFamily
                      font.pixelSize: 11
                      font.bold: true
                      color: isRepeater ? "#f59e0b" : Color.accent
                    }
                  }

                  // Line 2: Category Audit & Rationale Explanation (Full Unclipped Display)
                  BorderSurface {
                    width: parent.width
                    implicitHeight: catReasonCol.implicitHeight + Style.space(8)
                    radius: 3
                    color: modelData.category === "red"
                      ? Qt.rgba(0.94, 0.27, 0.27, 0.15)
                      : (modelData.category === "orange"
                          ? Qt.rgba(0.96, 0.62, 0.04, 0.15)
                          : Qt.rgba(0.06, 0.72, 0.51, 0.12))
                    borderSpec: Border.controlSpec("normal",
                      modelData.category === "red" ? "#ef4444" : (modelData.category === "orange" ? "#f59e0b" : "#10b981"),
                      Color.accent
                    )

                    Column {
                      id: catReasonCol
                      anchors.left: parent.left
                      anchors.right: parent.right
                      anchors.top: parent.top
                      anchors.margins: Style.space(4)
                      spacing: 2

                      Row {
                        spacing: Style.space(4)
                        Text {
                          textFormat: Text.PlainText
                          text: modelData.category === "red" ? "󰚌" : (modelData.category === "orange" ? "󰀝" : "󰄲")
                          font.family: root.contentFontFamily
                          font.pixelSize: 10
                          color: modelData.category === "red" ? "#ef4444" : (modelData.category === "orange" ? "#f59e0b" : "#10b981")
                        }
                        Text {
                          textFormat: Text.PlainText
                          text: modelData.categoryReason || "Active Network Host"
                          font.family: root.contentFontFamily
                          font.pixelSize: 10
                          font.bold: true
                          color: modelData.category === "red" ? "#ef4444" : (modelData.category === "orange" ? "#f59e0b" : "#10b981")
                          wrapMode: Text.WordWrap
                          width: hostCol.width - Style.space(32)
                        }
                      }
                    }
                  }

                  // Line 3: Vendor, MAC, Latency
                  Item {
                    width: parent.width
                    implicitHeight: Style.space(16)

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
                  }

                  // Line 4: Dedicated Open Ports Badges Row
                  Row {
                    visible: !isRepeater && modelData.portLabels && modelData.portLabels.length > 0
                    spacing: 4
                    Repeater {
                      model: (modelData.portLabels || []).slice(0, 6)
                      delegate: Rectangle {
                        height: 18
                        implicitWidth: portText.implicitWidth + 10
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

                  // Security Warnings Row with Detailed Recommendation
                  Column {
                    visible: !isRepeater && modelData.warnings && modelData.warnings.length > 0
                    width: parent.width
                    spacing: 4
                    Repeater {
                      model: modelData.warnings || []
                      delegate: BorderSurface {
                        width: parent.width
                        implicitHeight: warnCol.implicitHeight + 10
                        radius: 4
                        color: modelData.severity === "critical"
                          ? Qt.rgba(0.94, 0.27, 0.27, 0.12)
                          : (modelData.severity === "warning"
                              ? Qt.rgba(0.96, 0.62, 0.04, 0.12)
                              : Qt.rgba(0.23, 0.51, 0.96, 0.12))
                        borderSpec: Border.controlSpec("normal",
                          modelData.severity === "critical" ? "#ef4444" : (modelData.severity === "warning" ? "#f59e0b" : "#3b82f6"),
                          Color.accent
                        )

                        Column {
                          id: warnCol
                          anchors.left: parent.left
                          anchors.right: parent.right
                          anchors.top: parent.top
                          anchors.margins: 6
                          spacing: 2

                          Row {
                            spacing: 6
                            Text {
                              textFormat: Text.PlainText
                              text: modelData.severity === "critical" ? "󰚌" : (modelData.severity === "warning" ? "󰌵" : "󰋼")
                              font.family: root.contentFontFamily
                              font.pixelSize: 11
                              color: modelData.severity === "critical" ? "#ef4444" : (modelData.severity === "warning" ? "#f59e0b" : "#3b82f6")
                            }
                            Text {
                              textFormat: Text.PlainText
                              text: modelData.title || modelData.text
                              font.family: root.contentFontFamily
                              font.pixelSize: 11
                              font.bold: true
                              color: modelData.severity === "critical" ? "#ef4444" : (modelData.severity === "warning" ? "#f59e0b" : "#60a5fa")
                            }
                          }

                          Text {
                            visible: !!modelData.text && modelData.text !== modelData.title
                            textFormat: Text.PlainText
                            text: modelData.text
                            font.family: root.contentFontFamily
                            font.pixelSize: 10
                            color: root.contentForeground
                            wrapMode: Text.WordWrap
                            width: parent.width - 12
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
                    implicitHeight: Style.space(34)
                    radius: 4
                    color: downMouse.containsMouse ? Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.08) : Qt.rgba(root.contentForeground.r, root.contentForeground.g, root.contentForeground.b, 0.03)
                    borderSpec: Border.controlSpec("normal", Qt.darker(root.contentForeground, 3.5), Color.accent)

                    Item {
                      anchors.fill: parent
                      anchors.leftMargin: Style.space(10)
                      anchors.rightMargin: Style.space(10)

                      Row {
                        anchors.left: parent.left
                        anchors.right: downActionText.left
                        anchors.rightMargin: Style.space(8)
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: Style.space(8)

                        Text {
                          textFormat: Text.PlainText
                          text: modelData.typeIcon || "󰖩"
                          font.family: root.contentFontFamily
                          font.pixelSize: Style.font.bodySmall
                          color: "#f59e0b"
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
                          elide: Text.ElideRight
                        }

                        Text {
                          visible: !!modelData.friendlyName && modelData.friendlyName !== modelData.ip && modelData.friendlyName.indexOf(modelData.ip) === -1
                          textFormat: Text.PlainText
                          text: "(" + modelData.ip + ")"
                          font.family: "Monospace"
                          font.pixelSize: 10
                          color: root.contentSubtle
                          anchors.verticalCenter: parent.verticalCenter
                        }

                        Text {
                          textFormat: Text.PlainText
                          text: modelData.categoryReason || "Idle Client"
                          font.family: root.contentFontFamily
                          font.pixelSize: 10
                          color: root.contentSubtle
                          anchors.verticalCenter: parent.verticalCenter
                          elide: Text.ElideRight
                        }
                      }

                      Text {
                        id: downActionText
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
