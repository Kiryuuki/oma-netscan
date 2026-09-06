// Adapted from the connection switcher in karamble/demarchy (ISC).

pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls as QQC
import qs.Commons

// The pull-down range picker.
//
// A full-panel overlay holding a manually-positioned popup. It is placed rather
// than anchored because the trigger lives in the header: the popup is opened
// at the trigger's scene position and drops below it, or flips above when the
// card has no room underneath.
Item {
  id: root
  anchors.fill: parent
  z: 45

  // [{ id, name, detail, kind }], and which one is chosen. The first row is
  // the default route with an empty id; every other id is a CIDR.
  property var ranges: []
  property string activeId: ""

  readonly property bool opened: menu.opened

  // Where the keyboard is standing, which is not where the mouse is. Hover is
  // drawn by the row itself and never written here: Qt re-reports hover when
  // content moves under a still pointer, and that would drag the cursor back to
  // whatever the pointer happened to rest on.
  property int cursorIndex: 0

  signal chosen(string id)

  // Where the menu was asked to appear, kept because it cannot be placed until
  // it has a height.
  property real anchorX: 0
  property real anchorY: 0

  function openAt(sceneX, sceneY) {
    var local = root.mapFromGlobal(sceneX, sceneY)
    anchorX = local.x
    anchorY = local.y
    menu.open()
    place()
  }

  function close() { menu.close() }

  // A Popup does not build its contents until it is first opened, so on the
  // very first click its height is still zero: the fit test passes trivially
  // and the menu is drawn off the bottom. Placing again whenever the height
  // changes is what makes the first open behave like every one after it, and it
  // re-places the menu when a network appears or disappears.
  function place() {
    if (!menu.visible) return
    var tall = menu.height > 0 ? menu.height : menu.implicitHeight
    var x = Math.max(0, Math.min(anchorX, root.width - menu.width))
    var y = anchorY
    if (y + tall > root.height) y = y - tall
    if (y + tall > root.height) y = root.height - tall
    menu.x = Math.round(x)
    menu.y = Math.round(Math.max(0, y))
  }

  function moveCursor(delta) {
    var count = root.ranges ? root.ranges.length : 0
    if (count === 0) return
    // Wrap rather than clamp: this list is a handful of rows, and stopping at
    // the bottom would make the down key do nothing on the row you use most.
    cursorIndex = ((cursorIndex + delta) % count + count) % count
  }

  function chooseCursor() {
    var count = root.ranges ? root.ranges.length : 0
    if (cursorIndex < 0 || cursorIndex >= count) return
    var id = root.ranges[cursorIndex].id
    menu.close()
    root.chosen(id)
  }

  // Opening puts the keyboard on the range you are already scanning, so the
  // first keypress is one step from it rather than back at the top.
  function restCursorOnActive() {
    var list = root.ranges || []
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === root.activeId) { cursorIndex = i; return }
    }
    cursorIndex = 0
  }

  QQC.Popup {
    id: menu
    width: Style.space(300)
    implicitHeight: rows.implicitHeight + Style.space(8)
    padding: Style.space(4)
    modal: false
    focus: true
    closePolicy: QQC.Popup.CloseOnEscape | QQC.Popup.CloseOnPressOutside
    onHeightChanged: root.place()
    onOpened: {
      root.restCursorOnActive()
      root.place()
    }

    background: Rectangle {
      radius: Style.cornerRadius
      color: Color.popups.background
      border.width: Math.max(1, Style.normalBorderWidth)
      border.color: Color.popups.border
    }

    // The one place in this plugin that answers keys itself, and the reason is
    // the opposite of the usual rule. Inside an open Popup the popup takes every
    // key before the panel's key catcher sees it, so a PanelKeyCatcher binding
    // would look live and never run.
    contentItem: Column {
      id: rows
      focus: true
      spacing: Style.space(2)

      Keys.onPressed: function (event) {
        if (event.key === Qt.Key_J || event.key === Qt.Key_Down) {
          root.moveCursor(1)
          event.accepted = true
        } else if (event.key === Qt.Key_K || event.key === Qt.Key_Up) {
          root.moveCursor(-1)
          event.accepted = true
        } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
          root.chooseCursor()
          event.accepted = true
        }
        // Escape is absent on purpose: the popup's own CloseOnEscape already
        // closes it, and a second mechanism would be one too many.
      }

      Repeater {
        model: root.ranges

        Rectangle {
          id: row
          required property var modelData
          required property int index

          readonly property bool isActive: row.modelData.id === root.activeId
          readonly property bool hasCursor: root.cursorIndex === row.index

          width: menu.width - menu.leftPadding - menu.rightPadding
          implicitHeight: Style.space(38)
          radius: Style.cornerRadius
          color: row.isActive
                 ? Style.selectedFillFor(Color.popups.text, Color.accent)
                 : (rowHover.hovered || row.hasCursor
                    ? Style.hoverFillFor(Color.popups.text, Color.accent) : "transparent")
          // A border rather than a third fill: the range you are on already
          // owns the selected fill, and the keyboard has to stay visible while
          // standing on that row.
          border.width: row.hasCursor ? Math.max(1, Style.normalBorderWidth) : 0
          border.color: Style.normalBorderFor(Color.popups.text, Color.accent, Color.urgent)

          Column {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.leftMargin: Style.space(9)
            anchors.rightMargin: Style.space(9)
            anchors.verticalCenter: parent.verticalCenter
            spacing: 0

            Text {
              width: parent.width
              text: row.modelData.name
              textFormat: Text.PlainText
              color: Color.popups.text
              font.family: Style.font.family
              font.pixelSize: Style.font.bodySmall
              font.weight: Font.Medium
              elide: Text.ElideRight
            }
            // The interface and kind, not just the CIDR: two tunnels can easily
            // carry the same range, and this is the line that tells them apart.
            Text {
              width: parent.width
              text: row.modelData.detail
              textFormat: Text.PlainText
              color: Color.popups.text
              opacity: 0.5
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              elide: Text.ElideMiddle
            }
          }

          HoverHandler { id: rowHover; cursorShape: Qt.PointingHandCursor }
          TapHandler {
            onTapped: {
              menu.close()
              root.chosen(row.modelData.id)
            }
          }
        }
      }
    }
  }
}
