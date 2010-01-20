<?

header('Content-type: application/octet-stream');
header("Content-Disposition: attachment; filename=\"signed_invoice.xsig\"");
echo file_get_contents("signature.xsig");

?>
