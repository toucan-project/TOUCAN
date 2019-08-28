Option Explicit
Private Declare PtrSafe Function AddFontResource Lib "gdi32.dll" Alias "AddFontResourceA" (ByVal IpFileName As String) As Long

Sub GetFont()
Dim Result As Long
Dim FontUrl As String
FontUrl = ThisDocument.CustomDocumentProperties("CustomFontUrl")
Result = AddFontResource(FontUrl)
End Sub

Sub AutoExec()
GetFont
End Sub

