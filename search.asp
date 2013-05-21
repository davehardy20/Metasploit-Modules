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
<Br><Br><Br><Br><Br><Br>
<table border="0" width="200">
<tr>
 <td align="left"><br><br>
<h3>Employee Search</h3>
<form action="" method="GET" name="searchform">
<input type="text" name="search" id="search">
<input type="submit" value="Search">
</form>	
<%

'Sample Database Connection Syntax for ASP and SQL Server.

Dim oConn, oRs
Dim qry, connectstr
Dim db_name, db_username, db_userpassword
Dim db_server
Dim my_search

my_search = Request("search")
db_server = "Localhost"
db_name = "AdventureWorks"
db_username = "srv1user"
db_userpassword = "srv1password"
fieldname = "LoginID"
tablename = "HumanResources.Employee"

connectstr = "Driver={SQL Server};SERVER=" & db_server & ";DATABASE=" & db_name & ";UID=" & db_username & ";PWD=" & db_userpassword

Set oConn = Server.CreateObject("ADODB.Connection")
oConn.Open connectstr
 
'standard search query
qry = "SELECT * FROM " & tablename & " WHERE LoginID LIKE '%" & Request("search") & "%'"

Set oRS = oConn.Execute(qry)

   Response.Write "<strong>Search Results for:</strong>&nbsp;" & Request("search") & "<br>"

Do until oRs.EOF
   Response.Write "<a href=/employee.asp?id=" & oRs.Fields("EmployeeID") & ">" & oRs.Fields(fieldname) & "</a><br>"
   oRS.MoveNext
Loop
oRs.Close


Set oRs = nothing
Set oConn = nothing

%>

</body>
</html>