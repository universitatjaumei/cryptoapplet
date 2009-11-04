<?

//$sig=file_get_contents("php://input");
//$sig= str_replace("content=", "", $sig);
file_put_contents("signature.xsig", base64_decode($_POST['content']));


?>
