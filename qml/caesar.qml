import QtQuick 6
import QtQuick.Window 2.15
import QtQuick.Controls.Material 2.15

ApplicationWindow {
    id: window
    width: 250
    height: 70
    visible: true
    title: qsTr("successful")

    flags: Qt.WindowCloseButtonHint | Qt.WindowMinimizeButtonHint | Qt.CustomizeWindowHint | Qt.MSWindowsFixedSizeDialogHint | Qt.WindowTitleHint

    Material.theme: Material.Dark
    Material.accent: Material.LightBlue

    Rectangle {
        id: topBar
        height: 40
        color: Material.color(Material.Orange)
        anchors {
            left: parent.left
            right: parent.right
            top: parent.top
            margins: 15
        }
        radius: 5

        Text {
            text: qsTr("THE OPERATION IS SUCCESSFUL")
            anchors.verticalCenter: parent.verticalCenter
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            color: "#ffffff"
            anchors.horizontalCenter: parent.horizontalCenter
            font.pointSize: 10
        }
    }
}