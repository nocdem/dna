<?php
header('Content-Type: application/json');
$data = file_get_contents('data.json');
echo $data;
