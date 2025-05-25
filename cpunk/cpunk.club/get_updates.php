<?php
// Set headers to prevent caching
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");
header("Content-Type: text/plain");

// Output the contents of updates.txt
echo file_get_contents("updates.txt");
?>