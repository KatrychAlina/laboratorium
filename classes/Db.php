
<?php
class Db {
 private $mysqli; //Database variable
 private $select_result; //result
 public function __construct($serwer, $user, $pass, $baza) {
 $this->mysqli = new mysqli($serwer, $user, $pass, $baza);
 if ($this->mysqli->connect_errno) {
 printf("Connection to server failed: %s \n", $this->mysqli->connect_error);
 exit();
 }
 if ($this->mysqli->set_charset("utf8")) { //charset changed 
     }
     
 }
 function __destruct() {
 $this->mysqli->close();
 }
 public function select($sql) {
 //parameter $sql – select string
 //variable $results – association table with querry results
 $results=array();
 if ($result = $this->mysqli->query($sql)) {
 while ($row = $result->fetch_object()) {
 $results[]=$row;
 }
 $result->close();
 }
 $this->select_result=$results;
 return $results;
 }
 public function addMessage($name,$type,$content){
 $sql = "INSERT INTO message (`name`,`type`, `message`,`deleted`)
VALUES ('" . $name . "','" . $type . "','" . $content . "',0)";
 echo $sql;
 echo "<BR\>";
 return $this->mysqli->query($sql);
 }

 public function getMessage($message_id){
    if (!empty($this->select_result)) {
        foreach ($this->select_result as $message):
            if($message->id==$message_id){
                return $message->message;
            }
        endforeach;
    }
    return null;
}
public function update($id , $name , $type , $content){
    $sql = "UPDATE message SET name='$name' , type='$type', message='$content' WHERE id=$id";
    echo $sql;
    echo "<br\>";
    return $this->mysqli->query($sql);   
}
}
