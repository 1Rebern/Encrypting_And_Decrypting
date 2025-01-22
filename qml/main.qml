import QtQuick 6
import QtQuick.Window 2.15
import QtQuick.Controls 6
import QtQuick.Controls.Material 2.15
import QtQuick.Layouts 1.15

ApplicationWindow {
    id: window
    width: 450
    height: 270
    visible: true
    title: qsTr("program for encoding files")

    flags: Qt.WindowCloseButtonHint | Qt.WindowMinimizeButtonHint | Qt.CustomizeWindowHint | Qt.MSWindowsFixedSizeDialogHint | Qt.WindowTitleHint

    Material.theme: Material.Dark
    Material.accent: Material.LightBlue

    property bool isEncryptSelected: true
    property bool isEncryptRSASelected: true

    Rectangle {
        id: topBar
        height: 40
        color: Material.color(Material.Orange)
        anchors {
            left: parent.left
            right: parent.right
            top: parent.top
            margins: 10
        }
        radius: 5

        Text {
            text: qsTr("CHOOSE METHOD ENCRYPT/DECRYPT")
            anchors.verticalCenter: parent.verticalCenter
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            color: "#ffffff"
            anchors.horizontalCenter: parent.horizontalCenter
            font.pointSize: 10
        }
    }

    TabBar {
        id: bar
        anchors.top: topBar.bottom
        width: parent.width
        TabButton {
            text: qsTr("Caesar")
        }
        TabButton {
            text: qsTr("RSA")
        }
    }

    StackLayout {
        width: parent.width
        currentIndex: bar.currentIndex

        Item {
            id: homeTab
            ColumnLayout {
                anchors.fill: parent
                anchors.top: homeTab.bottom
                anchors.topMargin: 110
                
                RadioButton {
                    id: encryptRadio
                    text: qsTr("Encrypt")
                    checked: window.isEncryptSelected
                    onCheckedChanged: {
                        window.isEncryptSelected = checked;
                        leaveSpacesCheckbox.visible = true;
                        leaveCapitalCheckbox.visible = true;
                        decryptButton.visible = false;
                        encryptButton.visible = true;
                    }
                }

                RadioButton {
                    id: decryptRadio
                    text: qsTr("Decrypt")
                    checked: !window.isEncryptSelected
                    onCheckedChanged: {
                        window.isEncryptSelected = !checked;
                        leaveSpacesCheckbox.visible = false;
                        leaveCapitalCheckbox.visible = false;
                        encryptButton.visible = false;
                        decryptButton.visible = true;
                    }
                }

                
                Column{
                    anchors.top: encryptRadio.bottom
                    anchors.topMargin: -47
                    anchors.horizontalCenter: parent.horizontalCenter
                    rightPadding: 120
                    
                    CheckBox {
                        text: qsTr("Remove spaces")
                        id: leaveSpacesCheckbox
                        visible: window.isEncryptSelected
                        checked: false
                    }

                    CheckBox {
                        text: qsTr("Remove capital letters")
                        id: leaveCapitalCheckbox
                        visible: window.isEncryptSelected
                        checked: false
                    }
                }
            }
            TextField{
                    id: choiseFile
                    width: 210
                    text: qsTr("")
                    selectByMouse: true
                    placeholderText: qsTr("Enter file name(filename.txt|py)")
                    verticalAlignment: Text.AlignVCenter
                    anchors.top: homeTab.bottom
                    anchors.topMargin: 100
                    anchors.right: parent.right
                    anchors.rightMargin: 5   
                }

            CheckBox {
                text: qsTr("Save to a separate file            ")
                id: saveToSf
                checked: false
                anchors.top: homeTab.bottom
                anchors.topMargin: 160
                anchors.right: parent.right
            }

            Button{
                    id: encryptButton
                    width: 400
                    text: qsTr("Select")
                    anchors.horizontalCenter: parent.horizontalCenter 
                    anchors.top: homeTab.bottom
                    anchors.topMargin: 210
                    visible: window.isEncryptSelected
                    onClicked: backend.checkChoiseE(choiseFile.text, leaveSpacesCheckbox.checked , leaveCapitalCheckbox.checked, saveToSf.checked)
                }
            
            Button{
                    id: decryptButton
                    width: 400
                    text: qsTr("Select")
                    anchors.horizontalCenter: parent.horizontalCenter 
                    anchors.top: homeTab.bottom
                    anchors.topMargin: 210
                    visible: !window.isEncryptSelected
                    onClicked: backend.checkChoiseD(choiseFile.text, saveToSf.checked)
                }
        }
        Item {
            id: activityTab
            ColumnLayout {
                anchors.fill: parent
                anchors.left: parent.left
                anchors.leftMargin: 30
                anchors.top: activityTab.bottom
                anchors.topMargin: 110
                
                RadioButton {
                    id: encryptRadioRSA
                    text: qsTr("Encrypt")
                    checked: window.isEncryptRSASelected
                    onCheckedChanged: {
                        window.isEncryptRSASelected = checked;

                        decryptButtonRSA.visible = false;
                        encryptButtonRSA.visible = true;
                    }
                }

                RadioButton {
                    id: decryptRadioRSA
                    text: qsTr("Decrypt")
                    checked: !window.isEncryptRSASelected
                    onCheckedChanged: {
                        window.isEncryptRSASelected = !checked;
                        
                        encryptButtonRSA.visible = false;
                        decryptButtonRSA.visible = true;
                    }
                } 
            }

            TextField{
                id: choiceFileRSA
                width: 260
                text: qsTr("")
                selectByMouse: true
                placeholderText: qsTr("Enter file name(filename.txt)")
                verticalAlignment: Text.AlignVCenter
                anchors.top: activityTab.bottom
                anchors.topMargin: 100
                anchors.right: parent.right
                anchors.rightMargin: 5  
            }

            TextField{
                id: choiceKeySize
                width: 260
                text: qsTr("")
                visible: window.isEncryptRSASelected
                selectByMouse: true
                placeholderText: qsTr("Enter key size(2048|3072|4096)")//2048 = 126, 3072 = 189, 4096 = 252
                verticalAlignment: Text.AlignVCenter
                anchors.top: choiceFileRSA.bottom
                anchors.topMargin: 2
                anchors.right: parent.right
                anchors.rightMargin: 5  
            }

            TextField{
                id: choiceKeyFile
                width: 260
                text: qsTr("private_key.pem")
                visible: !window.isEncryptRSASelected
                selectByMouse: true
                placeholderText: qsTr("Enter key file name(private_key.pem)")
                verticalAlignment: Text.AlignVCenter
                anchors.top: choiceFileRSA.bottom
                anchors.topMargin: 2
                anchors.right: parent.right
                anchors.rightMargin: 5  
            }

            Button{
                    id: encryptButtonRSA
                    width: 400
                    text: qsTr("Select")
                    anchors.horizontalCenter: parent.horizontalCenter 
                    anchors.top: activityTab.bottom
                    anchors.topMargin: 210
                    visible: window.isEncryptRSASelected
                    onClicked: backend.checkChoiseRSAE(choiceFileRSA.text, choiceKeySize.text)
                }
            
            Button{
                    id: decryptButtonRSA
                    width: 400
                    text: qsTr("Select")
                    anchors.horizontalCenter: parent.horizontalCenter 
                    anchors.top: activityTab.bottom
                    anchors.topMargin: 210
                    visible: window.isEncryptRSASelected
                    onClicked: backend.checkChoiseRSAD(choiceFileRSA.text, choiceKeyFile.text)
                }
        }
    }

    Connections{
        target: backend

        function onSignalSelectE(boolValue){
            if(boolValue){
                var component = Qt.createComponent("caesar.qml")
                var win = component.createObject()
                win.show()
                visible = false
            }else{
                choiseFile.Material.foreground = Material.Pink
                choiseFile.Material.accent = Material.Pink
            }
        }

        function onSignalSelectD(boolValue){
            if(boolValue){
                var component = Qt.createComponent("caesar.qml")
                var win = component.createObject()
                win.show()
                visible = false
            }else{
                choiseFile.Material.foreground = Material.Pink
                choiseFile.Material.accent = Material.Pink
            }
        }

        function onSignalSelectERSA(boolValue){
            if(boolValue){
                var component = Qt.createComponent("caesar.qml")
                var win = component.createObject()
                win.show()
                visible = false
            }else{
                choiceFileRSA.Material.foreground = Material.Pink
                choiceFileRSA.Material.accent = Material.Pink
                choiceKeySize.Material.foreground = Material.Pink
                choiceKeySize.Material.accent = Material.Pink
            }
        }

        function onsignalSelectDRSA(boolValue){
            if(boolValue){
                var component = Qt.createComponent("caesar.qml")
                var win = component.createObject()
                win.show()
                visible = false
            }else{
                choiceFileRSA.Material.foreground = Material.Pink
                choiceFileRSA.Material.accent = Material.Pink
                choiceKeyFile.Material.foreground = Material.Pink
                choiceKeyFile.Material.accent = Material.Pink
            }
        }
    }

}