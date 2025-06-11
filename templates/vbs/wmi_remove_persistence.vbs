' wmi_remove_persistence.vbs
' This script removes WMI persistence components (filter, consumer, binding)
' and deletes the associated payload runner VBScript file.

Option Explicit
On Error Resume Next

Dim strComputer
Dim objWMIService
Dim objFSO
Dim bSomethingRemovedOrDeleted

' --- Configuration Placeholders (to be replaced by CAVE Python script) ---
' These names and path MUST match those used in wmi_setup_persistence.vbs
Const EVENT_FILTER_NAME     = "{{ event_filter_name }}"       ' e.g., "CAVEUpdaterFilter"
Const EVENT_CONSUMER_NAME   = "{{ event_consumer_name }}"     ' e.g., "CAVEUpdaterConsumer"
Const PAYLOAD_RUNNER_PATH   = "{{ payload_runner_path }}"     ' e.g., "C:\Users\Public\update_check.vbs"
' --- End Configuration Placeholders ---

bSomethingRemovedOrDeleted = False

' Step 1: Connect to WMI root\subscription namespace
strComputer = "."
Set objWMIService = GetObject("winmgmts:\\\\" & strComputer & "\\root\\subscription")

If Err.Number <> 0 Then
    ' WScript.Echo "Error: Failed to connect to WMI root\\subscription. " & Err.Description
    ' If cannot connect, cannot remove WMI objects, but still try to delete file.
Else
    ' Step 2: Delete __FilterToConsumerBinding
    ' Query for the specific binding to ensure it exists before attempting deletion.
    objWMIService.Delete "__FilterToConsumerBinding.Filter=""__EventFilter.Name='" & EVENT_FILTER_NAME & "'"",Consumer=""ActiveScriptEventConsumer.Name='" & EVENT_CONSUMER_NAME & "'"""
    If Err.Number = 0 Then
        ' WScript.Echo "Success: __FilterToConsumerBinding for Filter='" & EVENT_FILTER_NAME & "' and Consumer='" & EVENT_CONSUMER_NAME & "' removed."
        bSomethingRemovedOrDeleted = True
    ' Else
        ' WScript.Echo "Info: __FilterToConsumerBinding for Filter='" & EVENT_FILTER_NAME & "' and Consumer='" & EVENT_CONSUMER_NAME & "' not found or could not be removed. " & Err.Description
    End If
    Err.Clear

    ' Step 3: Delete ActiveScriptEventConsumer
    objWMIService.Delete "ActiveScriptEventConsumer.Name='" & EVENT_CONSUMER_NAME & "'"
    If Err.Number = 0 Then
        ' WScript.Echo "Success: ActiveScriptEventConsumer '" & EVENT_CONSUMER_NAME & "' removed."
        bSomethingRemovedOrDeleted = True
    ' Else
        ' WScript.Echo "Info: ActiveScriptEventConsumer '" & EVENT_CONSUMER_NAME & "' not found or could not be removed. " & Err.Description
    End If
    Err.Clear

    ' Step 4: Delete __EventFilter
    objWMIService.Delete "__EventFilter.Name='" & EVENT_FILTER_NAME & "'"
    If Err.Number = 0 Then
        ' WScript.Echo "Success: __EventFilter '" & EVENT_FILTER_NAME & "' removed."
        bSomethingRemovedOrDeleted = True
    ' Else
        ' WScript.Echo "Info: __EventFilter '" & EVENT_FILTER_NAME & "' not found or could not be removed. " & Err.Description
    End If
    Err.Clear
End If

Set objWMIService = Nothing

' Step 5: Delete the payload runner VBScript file from disk
Set objFSO = CreateObject("Scripting.FileSystemObject")
If Err.Number <> 0 Then
    ' WScript.Echo "Error: Failed to create FileSystemObject. Cannot delete payload file. " & Err.Description
Else
    If objFSO.FileExists(PAYLOAD_RUNNER_PATH) Then
        objFSO.DeleteFile PAYLOAD_RUNNER_PATH, True ' True to force deletion
        If Err.Number = 0 Then
            ' WScript.Echo "Success: Payload runner file '" & PAYLOAD_RUNNER_PATH & "' deleted."
            bSomethingRemovedOrDeleted = True
        ' Else
            ' WScript.Echo "Error: Failed to delete payload runner file '" & PAYLOAD_RUNNER_PATH & "'. " & Err.Description
        End If
    ' Else
        ' WScript.Echo "Info: Payload runner file '" & PAYLOAD_RUNNER_PATH & "' not found."
    End If
End If
Set objFSO = Nothing

'If bSomethingRemovedOrDeleted Then
    ' WScript.Echo "WMI Persistence removal process complete."
'Else
    ' WScript.Echo "WMI Persistence removal process complete. No components found or errors occurred."
'End If

WScript.Quit(0) ' Always quit with success, as it's a removal script.