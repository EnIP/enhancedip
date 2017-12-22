<html>
<body>
Thank you <?php echo $_POST["name"]; ?><br>
Your email address is: <?php echo $_POST["email"]; ?><br>
Comments received were: <?php echo $_POST["comments"]; ?><br>
Remote IP Address is: <?php echo $_SERVER["REMOTE_ADDR"]; ?><br>
</body>
</html>

<?php
//Store the data in a database.
$name     = htmlspecialchars($_POST["name"], ENT_QUOTES);
$email    = htmlspecialchars($_POST["email"], ENT_QUOTES);
$comments = htmlspecialchars($_POST["comments"], ENT_QUOTES);
$ipaddr   = $_SERVER["REMOTE_ADDR"];
$curdate  = date("Y-m-d");

/*
$subject = "$curdate $ipaddr";
$message = "From: $name <$email>\r\n$comments";
$res = mail('sam@enhancedip.org', $subject, $message);
*/

$dbconn = pg_connect("user=postgres dbname=enhancedip_feedback") or die('Could not connect: ' . pg_last_error());
$result = pg_query($dbconn, "INSERT INTO feedback VALUES('$name', '$email', '$comments', '$curdate', '$ipaddr');");
pg_close($dbconn);


?>
