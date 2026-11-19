import QtQml

// Tests deliver CLI replies explicitly, including replies from an old view.
QtObject {
  property var command: []
  property bool running: false
  property bool stdinEnabled: false
  property QtObject stdout
  property QtObject stderr
  property string lastInput: ""
  signal started()
  signal exited(int code, int exitStatus)
  onRunningChanged: { if (running) started() }
  function write(data) { lastInput = data }
  function finish() {
    running = false
    exited(0, 0)
  }
  function reply(data) {
    stdout.text = JSON.stringify(data)
    stdout.streamFinished()
    finish()
  }
}
