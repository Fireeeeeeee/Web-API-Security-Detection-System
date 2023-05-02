<?php

$servername = "localhost";
$db_username = "root";
$db_passwd = "";
$db_name = "waf";

$conn = new mysqli($servername,$db_username,$db_passwd,$db_name);
if($conn->connect_error){
    die("Á¬½ÓÊ§°Ü!".$conn->connect_error);
}
$id = $_GET['id'];
$sql = "select * from waf where id=".$id;
;$result = $conn->query($sql);
if ($result->num_rows > 0) {
    while($row = $result->fetch_assoc()) {
        echo "id: " . $row["id"]. " - Name: " . $row["name"]. "<br>";
    }
} else {
    echo "0 results";
}
?>