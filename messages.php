<?php
include_once "classes/Page.php";
include_once "classes/Db.php";
include_once "classes/Filter.php";

$db = new Db("localhost", "root", "", "news");

// adding new message
if (isset($_REQUEST['add_message'])) {
    $name = Filter::sanitizeString($_POST['name']);
    $type = Filter::sanitizeString($_POST['type']);
    $content = Filter::sanitizeString($_POST['content']);
    if (!$db->addMessage($name,$type,$content)){
        echo "Adding new message failed";
    }
}

if (isset($_REQUEST['update_message'])) {
    $id = $_REQUEST['id'];
    $name = $_REQUEST['name'];
    $type = $_REQUEST['type'];
    $content = $_REQUEST['content'];
    if (!$db->update($id,$name,$type,$content)){
        echo "Updating message failed";
    }
}

Page::display_header("Messages");

?>

<hr>
<p> Messages</p>
<ol>
<?php

$where_clause="";

// filtering messages
if (isset($_REQUEST['filter_messages'])) {
    $string = $_REQUEST['string'];
    $where_clause= " WHERE name LIKE '%" . $string . "%'";
}

$sql = "SELECT * from message" . $where_clause;
$messages = $db->select($sql);

foreach ($messages as $msg):
?>

<li><?php echo $msg->message; ?></li>
<form method="post" action="">
    <input type="hidden" name = "id" value="<?php echo $msg->id; ?>">
    <label>Name: </label>
    <input type="text" name = "name" value="<?php echo $msg->name; ?>"><br>
    <label>Type: </label>
    <input type="text" name = "type" value="<?php echo $msg->type; ?>"><br>
    <label> Content:</label>
    <textarea name="content"><?php echo $msg->message; ?></textarea><br>
    <input type = "submit" name="update_message" value = "Update">
</form>

<?php endforeach; ?>
</ol>

<hr>
<P>Messages filtering</P>
<form method="post" action="messages.php">
    <table>
        <tr>
            <td>Title contains: </td>
            <td>
                <label for="string"></label>
                <input required type="text" name="string" id="string" size="80"/>
            </td>
        </tr>
    </table>
    <input type="submit" id= "submit" value="Find messages" name="filter_messages">
</form>

<hr>

<P>Navigation</P>
<?php
Page::display_navigation();
Page::display_footer(); 
?>



