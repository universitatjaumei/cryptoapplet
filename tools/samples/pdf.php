<form method="post" action="signpdf.php" enctype="multipart/form-data">
    Select the PDF to be signed: <br/>
    <input checked id="pdf1" type="radio" name="pdf" value="/fich/f1.pdf"> <label for="pdf1">Fichero prueba 1 (149Kb) </label><a href="fich/f1.pdf"><img style="border: none;" src="img/pdf.gif" /></a></label><br/>
    <input disabled id="pdf2" type="radio" name="pdf" value="pdf2"> <label for="pdf2">Fichero prueba 2 (1MB) </label><a href="javascript:alert('Not available yet!');"><img style="border: none;" src="img/pdf.gif" /></a></label><br/>
    <input disabled id="pdf3" type="radio" name="pdf" value="pdf3"> <label for="pdf3"> Fichero prueba 3 (20MB) </label> <a href="javascript:alert('Not available yet!');"><img style="border: none;" src="img/pdf.gif" /></a><br/>
</form>

