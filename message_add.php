<?php
include_once "classes/Page.php";
include_once "classes/Db.php";
Page::display_header("Add message");
?>
<hr>
<P> Add message</P>
<form method="post" action="messages.php">
 <table>
 <tr>
     <td>Name</td>
 <td>
 <label for="name"></label>
 <input required type="text" name="name" id="name" size="56"/>
 </td>
 </tr>
 <tr>
 <td>Type</td>
 <td>
 <label for="type"></label>
 <select name="type" id="type">
 <option value="public">Public</option>
 <option value="private">Private</option>
 </select>
 </td>
 </tr>
 <tr>
 <td>Message content</td>
 <td>
 <label for="content"></label>
 <textarea required type="text" name="content" id="content" rows="10" cols="40">
 </textarea>
 </td>
 </tr>
 </table>
 <input type="submit" id= "submit" value="Add message" name="add_message">
</form>
<hr>
<P>Navigation</P>
<?php
Page::display_navigation();
?>
 </body>
</html>
