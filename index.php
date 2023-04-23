<?php
session_start();

include_once "classes/Page.php";
include_once "classes/Pdo_.php";
include_once "classes/Aes.php";

Page::display_header("Main page");

$pdo = new Pdo_();
$aes = new Aes();

if (isset($_POST['add_user'])) {
    $login = $_POST['login'];
    $email = $_POST['email'];
    $password = $_POST['password'];
    $password2 = $_POST['password2'];
    if ($password === $password2) {
        $pdo->add_user($login, $email, $password);
    } else {
        echo 'Passwords don\'t match';
    }
}

if (isset($_POST['log_user_in'])) {
    $login = $_POST['login'];
    $password = $_POST['password'];
    $pdo->log_user_in($login, $password);
}

if (isset($_POST['change_password'])) {
    $login = $_POST['login'];
    $old_password = $_POST['old_password'];
    $new_password = $_POST['new_password'];
    $new_password2 = $_POST['new_password2'];
    if ($new_password === $new_password2) {
        $pdo->change_password($login, $old_password, $new_password);
    } else {
        echo 'New passwords doesn\'t match';
    }
}

// Log user in

?>

<h2> Main page</h2>
<!---------------------------------------------------------------------->
<hr>
<p> Register new user</p>
<form method="post" action="index.php">
    <table>
        <tr>
            <td>login</td>
            <td>
                <label for="login"></label>
                <input required type="text" name="login" id="login" size="40"/>
            </td>
        </tr>
        <tr>
            <td>email</td>
            <td>
                <label for="email"></label>
                <input required type="email" name="email" id="email" size="40"/>
            </td>
        </tr>
        <tr>
            <td>password</td>
            <td>
                <label for="password"></label>
                <input required type="password" name="password" id="password" size="40"/>
            </td>
        </tr>
        <tr>
            <td>repeat password</td>
            <td>
                <label for="password2"></label>
                <input required type="password" name="password2" id="password2" size="40"/>
            </td>
        </tr>
    </table>
    <input type="submit" id="submit" value="Create account" name="add_user">
</form>
<!---------------------------------------------------------------------->
<hr>
<P> Log in</P>
<form method="post" action="index.php">
    <table>
        <tr>
            <td>login</td>
            <td>
                <label for="name"></label>
                <input required type="text" name="login" id="login" size="40" value="test123"/>
            </td>
        </tr>
        <tr>
            <td>password</td>
            <td>
                <label for="name"></label>
                <input required type="password" name="password"
                       id="password" size="40" value="student"/>
            </td>
        </tr>
    </table>
 <input type="submit" id= "submit" value="Log in" name="log_user_in">
</form>
<form method="post">
    <label for="new_password">New password:</label>
    <input type="password" name="new_password" id="new_password" required>
    <button type="submit" name="submit">Change password</button>
</form>

<!-- </body>-->
<!--</html>-->
