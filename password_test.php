<?php
include("password.php");
//generate a password 16 characters in length
//this doesn't encrypt the password though but gives you a string
//of random characters you can provide as a "suggestion" to users
$new_pass = StrongPass::make(16);
echo "Generated password : $new_pass";

echo "<br/><br/>";
echo "Generating password/hash combo...<br/><br/>";
//create an instance of StrongPass and generate a password/hash combo
//for a password 16 characters long
$pw = new StrongPass(16);

//retrieve the values of the password and the corresponding hash value
echo "Generated password is ".$pw->pass."<br/>";
echo "Generated hash for password is {$pw->hash}";

echo "<br/><br/>";
echo "Check if the password '".$pw->pass."' and hash match...<br/>";
//check that the password and hash are equivalent
//this will return a "true"
if($pw->confirm($pw->pass, $pw->hash))
    echo "The MD5 password is correct";
else
    echo "The MD5 password is wrong";
    
   
echo "<br/><br/>";
    
$pw2 = new StrongPass(8, "thisIsMyPassword", "sha1");

if($pw2->confirm($pw2->pass, $pw2->hash))
    echo "The SHA password is correct";
else
    echo "The SHA password is wrong";
    
echo "<br/><br/>";

?>