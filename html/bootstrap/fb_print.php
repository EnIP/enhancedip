<html>
<link href="table.css" rel="stylesheet">

<body>
<table border="1">

<?php
$dbconn = pg_connect("user=postgres dbname=enhancedip_feedback") or die('Could not connect: ' . pg_last_error());
$result = pg_query($dbconn, "select * from feedback;");

print "<tr>";
print "<td>Date</td>";
print "<td>Name</td>";
print "<td>Email</td>";
print "<td>Comments</td>";
print "<td>IP Address</td>";
print "</tr>";

while($row = pg_fetch_row($result)){
	print "<tr>";
	$date = htmlspecialchars($row[3], ENT_QUOTES);
	print "<td>$date</td>";	

	$name = htmlspecialchars($row[0], ENT_QUOTES);
	print "<td>$name</td>";	

	$email = htmlspecialchars($row[1], ENT_QUOTES);
	print "<td>$email</td>";	

	$comments = htmlspecialchars($row[2], ENT_QUOTES);
	print "<td>$comments</td>";	

	$ipaddr = htmlspecialchars($row[4], ENT_QUOTES);
	print "<td>$ipaddr</td>";	
	print "</tr>";
}

pg_close($dbconn);
?>

</table>
</body>
</html>
