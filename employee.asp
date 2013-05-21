<html>
<body>

<table align="left" border="0" width="200">
<tr>
 <td align="center">
	<font size="20">MBA</font><br>
 	My Bad Application
 </td>
</tr>
<tr>
 <td align="center">
	<a href="/search.asp">Employee Search</a>	
 </td>
</tr>
</table>

<Br><Br><Br><Br><Br><Br><Br><Br>
<table border="0"
<tr>
 <td align="left">
<h3>Employee Information</h3>
<%

'Sample Database Connection Syntax for ASP and SQL Server.

Dim oConn, oRs
Dim qry, connectstr
Dim db_name, db_username, db_userpassword
Dim db_server
Dim my_search

id = Request("id")
db_server = "localhost"
db_name = "AdventureWorks"
tablename = "HumanResources.Employee"
db_username = "srv1user"
db_userpassword = "srv1password"
fieldname = "LoginID"


connectstr = "Driver={SQL Server};SERVER=" & db_server & ";DATABASE=" & db_name & ";UID=" & db_username & ";PWD=" & db_userpassword

Set oConn = Server.CreateObject("ADODB.Connection")
oConn.Open connectstr
 
'standard search query
qry = "SELECT * FROM " & tablename & " WHERE EmployeeID = " & Request("id")
'qry = "SELECT * FROM " & tablename

Set oRS = oConn.Execute(qry)

Do until oRs.EOF

   Response.Write "<strong>ID:</strong>&nbsp;" & oRs.Fields("EmployeeID") & "<br>"
   Response.Write "<strong>Title:&nbsp;</strong>" & oRs.Fields("title") & "<br>"
   Response.Write "<strong>User:&nbsp;</strong>" & oRs.Fields(fieldname) & "<br>"
   Response.Write "<strong>Birth Date:&nbsp;</strong>" & oRs.Fields("birthdate") & "<br>"

   oRS.MoveNext
Loop
oRs.Close


Set oRs = nothing
Set oConn = nothing

%>
 </td>
</tr>
</table>
</body>
</html>