<?php
/*
Plugin Name: Sucuri Security
Plugin URI: http://wordpress.sucuri.net/
Description: WordPress Audit log and integrity checking plugin. Developed by Sucuri Security, this plugin will monitor your Wordpress installation for the latest attacks and provide visibility to what is happening inside (auditing). It will also keep track of system events, like logins, logouts, failed logins, new users, file changes, etc. When an attack is detected it will block the IP address via .htaccess and internally on WP. 
Author: http://sucuri.net
Version: 1.5.2
Author URI: http://sucuri.net
*/

/*
    Partially Integrated from WPsyslog and wpsyslog2 (http://www.ossec.net).

	WPsyslog -- Global logging facility for WordPress
	Copyright (C) 2007 Alex Guensche <http://www.zirona.com>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation in the Version 2.
	
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
*/
//error_reporting(0);



/* Starting Sucuri side bar. */
function sucuri_menu() 
{
    add_menu_page('Sucuri Security', 'Sucuri Security', 'manage_options', 
                  'sucurisec', 'sucuri_admin_page');
    add_submenu_page('sucurisec', 'Dashboard', 'Dashboard', 'manage_options',
                     'sucurisec', 'sucuri_admin_page');
    add_submenu_page('sucurisec', 'Settings', 'Settings', 'manage_options',
                     'sucurisec_settings', 'sucuri_settings_page');
    add_submenu_page('sucurisec', 'Malware Scanning', 'Malware Scanning', 
                     'manage_options',
                     'sucurisec_malwarescan', 'sucuri_malwarescan_page');
    add_submenu_page('sucurisec', '1-Click Hardening', '1-Click Hardening', 
                     'manage_options',
                     'sucurisec_hardening', 'sucuri_hardening_page');
}



/* Modifying API key. */
function sucuri_modify_values()
{
    if(isset($_POST['wpsucuri-newkey']))
    {
        $newkey = htmlspecialchars(trim($_POST['wpsucuri-newkey']));
        if(preg_match("/^[a-zA-Z0-9]+$/", $newkey, $regs, PREG_OFFSET_CAPTURE,0))
        {
            $res = sucuri_send_log($newkey, "INFO: Authentication key added and plugin enabled.");
            if($res == 1)
            {
                update_option('sucuri_wp_key', $newkey);

                if(!wp_next_scheduled( 'sucuri_hourly_scan')) 
                {
	            wp_schedule_event(time() + 2, 'hourly', 'sucuri_hourly_scan');
                }
                if(!wp_next_scheduled('sucuri_dailydb_scan'))
                {
                    wp_schedule_event(time() + 240, 'daily', 'sucuri_dailydb_scan');
                }
                if(!wp_next_scheduled('sucuri_dailyfs_scan'))
                {
                    wp_schedule_event(time() + 360, 'daily', 'sucuri_dailyfs_scan');
                }
                return(NULL);
            }
            else
            {
                return("ERROR: Key not accepted by sucuri.net.");
            }
        }
        else
        {
            return("ERROR: Invalid key.");
        }
    }
    if(isset($_POST['sucuri_dbb']))
    {
        update_option('sucuri_wp_dbb', 'enabled');
    }
    else
    {
        update_option('sucuri_wp_dbb', 'disabled');
    }
    if(isset($_POST['sucuri_fsb']))
    {
        update_option('sucuri_wp_fsb', 'enabled');
    }
    else
    {
        update_option('sucuri_wp_fsb', 'disabled');
    }
    if(isset($_POST['sucuri_re']))
    {
        update_option('sucuri_wp_re', 'enabled');
    }
    else
    {
        update_option('sucuri_wp_re', 'disabled');
    }
}



/* Sucuri one-click hardening page. */
function sucuri_hardening_page()
{
    $U_ERROR = NULL;
    if(!current_user_can('manage_options'))
    {
        wp_die(__('You do not have sufficient permissions to access this page.') );
    }
    include_once("sucuri_hardening.php");



    /* Hardening page. */
    echo '<div class="wrap">';
    echo '<h2>Sucuri 1-Click WordPress Hardening</h2>';

    echo '<h3>Secure your WordPress with a one-click hardening.</h3>'; 

    echo "<hr />";
    sucuri_harden_version();
    echo "<hr />";
    sucuri_harden_removegenerator();
    echo "<hr />";
    sucuri_harden_upload();
    echo "<hr />";
    sucuri_harden_dbtables();
    echo "<hr />";
    sucuri_harden_adminuser();
    echo "<hr />";
    sucuri_harden_keys();
    echo "<hr />";
    sucuri_harden_wpconfig();
    echo "<hr />";
    sucuri_harden_perms();
    echo "<hr />";
    sucuri_harden_readme();
    echo "<hr />";
    sucuri_harden_phpversion();
    echo "<hr />";
    ?>
    <br /><br />
    <b>If you have any question about these checks or this plugin, contact us at support@sucuri.net or visit <a href="http://sucuri.net">http://sucuri.net</a></b>
   <br />

    </div>
    <?php
}



/* Sucuri malware scan page. */
function sucuri_malwarescan_page()
{
    $U_ERROR = NULL;
    if(!current_user_can('manage_options'))
    {
        wp_die(__('You do not have sufficient permissions to access this page.') );
    }


    if(isset($_POST['wpsucuri-doscan']))
    {
        /* Admin header. */
        echo '<div class="wrap">';
        ?>
        <iframe style="overflow:hidden" width="100%" height="1350px" src='http://sitecheck.sucuri.net/scanner/?wp-style&scan=<?php echo home_url();?>'>
        Unable to load iframe.
        </iframe>
        <br />
        <hr />
        <h3><i>Scanning by <a href="http://sucuri.net">Sucuri Security</a> | <a href="https://support.sucuri.net">Support & Help</a></i></h3>
        </div>
        <?php
        return(1);
    }


    /* Setting's header. */
    echo '<div class="wrap">';
    echo '<h2>Sucuri Malware Scanner</h2>';

    echo '<h3>Execute an external malware scanner on your site, using the <a href="http://sucuri.net">Sucuri</a> scanner. It will alert you if your site is compromised with malware, spam, defaced, etc.</h3>'; 
    ?>

    <form action="" method="post">
    <input type="hidden" name="wpsucuri-doscan" value="wpsucuri-doscan" />
    <input class="button-primary" type="submit" name="wpsucuri_doscanrun" value="Scan this site now!" />
    </form>

    <?php
}



/* Sucuri setting's page. */
function sucuri_settings_page()
{
    $U_ERROR = NULL;
    if(!current_user_can('manage_options'))
    {
        wp_die(__('You do not have sufficient permissions to access this page.') );
    }


    /* Setting's header. */
    echo '<div class="wrap">';
    echo '<h2>Sucuri Security Settings</h2>';


    if(isset($_POST['wpsucuri-modify-values']))
    {
        $U_ERROR = sucuri_modify_values();
    }


    $sucuri_wp_key = NULL;
    $sucuri_key_msg = "";
    $sucuri_wp_key = get_option('sucuri_wp_key');
    if($sucuri_wp_key === FALSE)
    {
        echo '<h3>Not configured yet. Please login to <a target="_blank" href="https://wordpress.sucuri.net">https://wordpress.sucuri.net</a> to get your authentication (API) key.</h3>';
        echo '<h3><i>*This plugin is currently only for Sucuri registered users. If you do not have an account, please create one at: <a target="_blank" href="http://sucuri.net/wordpress-security-monitoring">http://sucuri.net/wordpress-security-monitoring</a></i></h3>';
        echo '<h3><i>**If you already have an API key, just paste it below.</i></h3>';
        $sucuri_key_msg = '<b>Sucuri API Key:</b> &nbsp; &nbsp; <input type="text" name="wpsucuri-newkey" size="40" value="" /><br />(<i>This API key is used to authenticate your WordPress with Sucuri</i>)</br >&nbsp;<br /><br />';
    }
    else
    {
        $sucuri_key_msg = '<h3>Your Sucuri API Key: &nbsp; &nbsp; <i>'.$sucuri_wp_key.'</i></h3>';
        $sucuri_key_msg .= 
        '
        <h3>Quick Links</h3>
        
        <a href="admin.php?page=sucurisec">Sucuri Dashboard</a><br /> &nbsp; View your auditing events, backup information, etc. <br />

        <a href="admin.php?page=sucurisec_hardening">One click Hardening</a><br /> &nbsp; Verify if you are using the latest security options on WordPress and apply them easily. <br />

        <a href="admin.php?page=sucurisec_malwarescan">Malware scanning</a><br /> &nbsp; Scan your site for malware, using the Sucuri security scanner.<br />

        <a href="https://wordpress.sucuri.net">https://wordpress.sucuri.net</a><br /> &nbsp;  Management interface &nbsp; (<i>requires a Sucuri.net account</i>)<br /><br />
       <hr />


';
    }

    if($U_ERROR != NULL)
    {
        echo "<br /><h3><i style='font-color:#c0c0c0;'>--&gt;$U_ERROR</i></h3><br />";
    }
    
    ?>

    <hr />
    <form action="" method="post">
    <input type="hidden" name="wpsucuri-modify-values" value="wpsucuri-modify-values" />

    <?php echo $sucuri_key_msg; ?>
    <table>
    <tr><td><b>Integrity checking:&nbsp; </b></td><td><input type="checkbox" name="sucuri_ic" value="1" checked="checked" disabled="disabled"  /></td></tr>
    <tr><td>(<i>*Enables integrity monitoring of your files</i>)</td><td></td></tr>
    <tr><td>&nbsp; </td><td>&nbsp; </td></tr>

    <tr><td><b>Event auditing: &nbsp;</b></td><td><input type="checkbox" name="sucuri_ea" value="1" checked="checked" disabled="disabled" /></td></tr>

    <tr><td>(<i>*Enables and create an audit log for WordPress</i>)</td><td></td></tr>
    <tr><td>&nbsp; </td><td>&nbsp; </td></tr>
    <?php
    $ck = get_option('sucuri_wp_re');
    $ck_val = ' checked="checked"';
    if($ck !== FALSE && $ck == 'disabled')
    {
        $ck_val = '';
        return(NULL);
    }
    ?>
    <tr><td><b>Remediation: &nbsp;</b></td><td><input type="checkbox" name="sucuri_re" value="1"<?php echo $ck_val;?> /></td></tr>
    <tr><td>(<i>Allows the plugin to block the IP address of an attacker</i>)</td><td></td></tr>
    <tr><td>&nbsp; </td><td>&nbsp; </td></tr>

    <?php
    $ck = get_option('sucuri_wp_dbb');
    $ck_val = ' checked="checked"';
    if($ck !== FALSE && $ck == 'disabled')
    {
        $ck_val = '';
        return(NULL);
    }
    ?>
    <tr><td><b>Database backup: &nbsp; </b></td> <td><input type="checkbox" name="sucuri_dbb" value="1"<?php echo $ck_val;?> /></td></tr>
    <tr><td>(<i>Enables or disables database backup</i>)</td><td></td></tr>
    <tr><td>&nbsp; </td><td>&nbsp; </td></tr>

    <?php
    $ck = get_option('sucuri_wp_fsb');
    $ck_val = ' checked="checked"';
    if($ck !== FALSE && $ck == 'disabled')
    {
        $ck_val = '';
        return(NULL);
    }
    ?>
    <tr><td><b>Filesystem backup: &nbsp; &nbsp; </b> &nbsp; </td> <td><input type="checkbox" name="sucuri_fsb" value="1"<?php echo $ck_val;?> /></td></tr>
    <tr><td>(<i>Enables or disables themes/config backup</i>)</td><td></td></tr>

    <tr><td> &nbsp; </td> <td> &nbsp; </td></tr>

    <tr><td> &nbsp; <input class="button-primary" type="submit" name="wpsucuri_domodify" value="Save values"></td><td> &nbsp; </td></tr>
    </table>
    
    </form>

    <hr />
    <?php if($sucuri_wp_key !== FALSE) { ?>
    <b>List of blacklisted IP addresses:</b><br /><br />
    <?php
    $totalips = 0;
    $errrm = NULL;

    if(isset($_POST['wpsucuri_removeip']) && strlen($_POST['wpsucuri_removeip']) > 6)
    {
        $iptorm = explode(' ', htmlspecialchars($_POST['wpsucuri_removeip']));
        if($iptorm !== FALSE && !empty($iptorm) && strlen($iptorm[0]) > 4)
        {
            # removig ip: $iptorm[0];
            $blfile = file(ABSPATH."/wp-content/uploads/sucuri/block.php",FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if($blfile !== FALSE)
            {
                $finalstr = "";
                foreach($blfile as $line)
                {
                    if($line == $iptorm[0]) { continue; }
                    $finalstr = $finalstr.$line."\n";
                }
                if(file_put_contents(ABSPATH."/wp-content/uploads/sucuri/block.php", $finalstr) === FALSE)
                {
                    $errrm = "Unable to re-write .htaccess file. Not removed.";
                }
            }
            else
            {
                $errrm = "Unable to open block list. Not removed.";
            }

            $blfile = file(ABSPATH."/.htaccess",FILE_IGNORE_NEW_LINES);
            if($blfile !== FALSE)
            {
                $finalstr = "";
                foreach($blfile as $line)
                {
                    if($line == "deny from ".$iptorm[0]." #ADDED BY SUCURI") { continue; }
                    $finalstr = $finalstr.$line."\n";
                }
                if(file_put_contents(ABSPATH."/.htaccess", $finalstr) === FALSE)
                {
                    $errrm = "Unable to re-write .htaccess file. Not removed.";
                }
            }
            else
            {
                $errrm = "Unable to open .htaccess file. Not removed.";
            }

            if($errrm != NULL)
            {
                echo '<div id="message" class="updated"><p>'.$errrm.'</p></div>';
            }
            else
            {
                echo '<div id="message" class="updated"><p>IP address removed.</p></div>';
            }
        }
    }



    if(is_readable(ABSPATH."/wp-content/uploads/sucuri/block.php"))
    {
        $listofips = file(ABSPATH."/wp-content/uploads/sucuri/block.php",FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if(count($listofips > 1))
        {
            ?>
            <form action="" method="post">
            <input type="hidden" name="wpsucuri-removeblock" value="wpsucuri-removeblock" />
            <?php
            foreach($listofips as $uniqip)
            {
                if(strncmp($uniqip, "<", 1) == 0 ||
                   strncmp($uniqip, "#", 1) == 0)
                {
                    continue;
                }
               $uniqip = htmlspecialchars($uniqip);
                echo "<input type=\"submit\" name=\"wpsucuri_removeip\" value=\"$uniqip - Click to remove\" /><br />\n";
                $totalips++;
            }
            echo "</form>";
        }
    }
    if($totalips == 0)
    {
        echo "<i>No IP addresses blacklisted so far.</i><br /><br />\n";
    }
    else
    {
        echo "<br />\n";
    }
    } else { ?>

    <br />
    <i>*This option is mandatory and can't be disabled.</i>
    <?php } ?>
    <br />

    <?php
    echo '</div>';
}



/* Sucuri's dashboard (main admin page) */
function sucuri_admin_page()
{
    $U_ERROR = NULL;
    if(!current_user_can('manage_options'))
    {
        wp_die( __('You do not have sufficient permissions to access this page.') );
    }

    $sucuri_wp_key = NULL;
    $sucuri_wp_key = get_option('sucuri_wp_key');
    if(isset($_POST['wpsucuri-modify-values']))
    {
        sucuri_settings_page();
        return(1);
    }
    else if($sucuri_wp_key === FALSE)
    {
        sucuri_settings_page();
        return(1);
    }


    /* Admin header. */
    echo '<div class="wrap">';
    ?>
    <iframe style="overflow:hidden" width="100%" height="2250px" src='https://wordpress.sucuri.net/single.php?k=<?php echo $sucuri_wp_key;?>'>
    Unable to load iframe.
    </iframe>
    <br />
    <hr />
    <h3><i>Plugin developed by <a href="http://sucuri.net">Sucuri Security</a> | <a href="https://support.sucuri.net">Support & Help</a></i></h3>
    </div>
    <?php
}



/* Deactivates the plugin. */
function sucuri_deactivate_scan() 
{
    wp_clear_scheduled_hook('sucuri_hourly_scan');
    wp_clear_scheduled_hook('sucuri_daily_scan');
    wp_clear_scheduled_hook('sucuri_dailydb_scan');
    wp_clear_scheduled_hook('sucuri_dailyfs_scan');
    delete_option('sucuri_wp_key');
}



/* Activates the hourly scan. */
function sucuri_activate_scan() 
{
    if(!is_dir(ABSPATH."/wp-content/uploads"))
    {
        mkdir(ABSPATH."/wp-content/uploads/");
    }
    mkdir(ABSPATH."/wp-content/uploads/sucuri");
    touch(ABSPATH."/wp-content/uploads/sucuri/index.html");
}



/* Check if backup completed. */
function sucuri_backup_docheck($type, $runtime)
{
    if($runtime == 0)
    {
        touch(ABSPATH."/wp-content/uploads/sucuri/.started-".$type);
    }
    else if($runtime == -1)
    {
        unlink(ABSPATH."/wp-content/uploads/sucuri/.started-".$type);
    }
    else if(is_readable(ABSPATH."/wp-content/uploads/sucuri/.started-".$type))
    {
        $lastchanged = filemtime(ABSPATH."/wp-content/uploads/sucuri/.started-".$type);
        if($lastchanged < (time(0) - $runtime))
        {
            return(1);
        }
    }
    return(0);
}



/* Avoid running twice (save / set last running time) */
function sucuri_verify_run($type, $runtime)
{
    if(!is_readable(ABSPATH."/wp-content/uploads/sucuri/.".$type))
    {
        if(!is_dir(ABSPATH."/wp-content/uploads/sucuri"))
        {
            mkdir(ABSPATH."/wp-content/uploads/sucuri");
            touch(ABSPATH."/wp-content/uploads/sucuri/index.html");
        }
        touch(ABSPATH."/wp-content/uploads/sucuri/.".$type);
        return(true);
    }

    $lastchanged = filemtime(ABSPATH."/wp-content/uploads/sucuri/.".$type);
    if($lastchanged > (time(0) - $runtime))
    {
        return(FALSE);
    }

    touch(ABSPATH."/wp-content/uploads/sucuri/.".$type);
    return(true);
}



/* Clear saved db/fs backup files. */
function sucuri_clear_cache()
{
    if(!is_dir(ABSPATH."/wp-content/uploads/sucuri"))
    {
        return;
    }

    $list_of_files = scandir(ABSPATH."/wp-content/uploads/sucuri");
    if($list_of_files === FALSE)
    {
        return;
    }

    foreach($list_of_files as $myfile)
    {
        if(strncmp($myfile, ".", 1) == 0)
        {
            continue;
        }
        if(strpos($myfile, ".zip") !== FALSE ||
           strpos($myfile, ".gz") !== FALSE)
        {
            $fpath = ABSPATH."/wp-content/uploads/sucuri/".$myfile;
            $modtime = filemtime($fpath);
            if($modtime < (time(0) - 172800))
            {
                unlink($fpath);
            }
        }
    }
}



/* Executes the daily db backups. */
function sucuri_dodailydb_scan() 
{
    $backup_error = NULL;
    $sucuri_wp_key = get_option('sucuri_wp_key');
    if($sucuri_wp_key === FALSE)
    {
        return(NULL);
    }

    $dbb = get_option('sucuri_wp_dbb');
    if($dbb !== FALSE && $dbb == 'disabled')
    {
        return(NULL);
    }

    if(sucuri_verify_run("db", 7200) === FALSE)
    {
        return(NULL);
    }

    sucuri_backup_docheck("db", 0);
    sucuri_send_log($sucuri_wp_key, "DEBUG: Starting WordPress DB Backup ...", 1);
    sucuri_clear_cache();
    @ini_set("max_execution_time","9000");
    @set_time_limit(9000);
    $output = sucuri_dobackup_db($backup_error);
    if($output != NULL)
    {
        sucuri_send_log($sucuri_wp_key, "WordPress DB at: $output", 1);
    }
    else
    {
        sucuri_send_log($sucuri_wp_key, "WordPress DB backup failed: $backup_error", 1);
    }
    sucuri_backup_docheck("db", -1);
}



/* Executes the daily fs backups. */
function sucuri_dodailyfs_scan() 
{
    $backup_error = NULL;
    $sucuri_wp_key = get_option('sucuri_wp_key');
    if($sucuri_wp_key === FALSE)
    {
        return(NULL);
    }

    $fsb = get_option('sucuri_wp_fsb');
    if($fsb !== FALSE && $fsb == 'disabled')
    {
        return(NULL);
    }

    if(sucuri_verify_run("fs", 7200) === FALSE)
    {
        return(NULL);
    }

    sucuri_clear_cache();
    sucuri_backup_docheck("fs", 0);
    sucuri_send_log($sucuri_wp_key, "DEBUG: Starting WordPress FS Backup ...", 1);
    @ini_set("max_execution_time","9000");
    @set_time_limit(9000);
    $output = sucuri_dobackup_fs($backup_error);
    if($output != NULL)
    {
        sucuri_send_log($sucuri_wp_key, "WordPress Backup at: $output", 1);
    }
    else
    {
        sucuri_send_log($sucuri_wp_key, "WordPress FS backup failed: $backup_error", 1);
    }
    sucuri_backup_docheck("fs", -1);
}



/* Executes the daily fs backups. */
function sucuri_dobackup_fs(&$USE_error)
{
    /* Creating backup file */
    if(!is_dir(ABSPATH."/wp-content/uploads/sucuri"))
    {
        mkdir(ABSPATH."/wp-content/uploads/sucuri");
        touch(ABSPATH."/wp-content/uploads/sucuri/index.html");
    }
    if(!is_readable(ABSPATH."/wp-content/uploads/sucuri/index.html"))
    {
        $USE_error = "Unable to create temporary files at:".
                     ABSPATH."/wp-content/uploads/sucuri/";
        return(NULL);
    }

    $curr_theme = substr(strrchr(get_bloginfo('template_directory'), "/"), 1);
    $curr_theme = ABSPATH."/wp-content/themes/$curr_theme";
    if(!is_dir($curr_theme))
    {
        $USE_error = "Unable to get current theme at: $curr_theme (did you switch themes?)";
        return(NULL);
    }

    $rand1 = rand();
    $rand_file = "fs".md5($rand1)."-".time();

    require_once('sucuri-pclzip.php');
    $backup_f = new PclZip(ABSPATH."/wp-content/uploads/sucuri/$rand_file.zip");

    /* Adding WordPress config. */
    $wpconf = "";
    if(is_readable(ABSPATH."/wp-config.php"))
    {
        $wpconf = ABSPATH."/wp-config.php";
        $ret = $backup_f->add("$wpconf",
                          PCLZIP_OPT_REMOVE_PATH, ABSPATH);
    }
    else if(is_readable(ABSPATH."/wp-config.php"))
    {
        $wpconf = ABSPATH."/../wp-config.php";
        $ret = $backup_f->add("$wpconf",
                          PCLZIP_OPT_REMOVE_PATH, dirname(realpath(ABSPATH."/../wp-config.php")));
    }
    /* Adding .htaccess */
    if(is_readable(ABSPATH."/.htaccess"))
    {
        $ret = $backup_f->add(ABSPATH."/.htaccess",
                          PCLZIP_OPT_REMOVE_PATH, ABSPATH);
    }

    $ret = $backup_f->add("$curr_theme",
                          PCLZIP_OPT_REMOVE_PATH, ABSPATH);
    if($ret == 0)
    {
        $USE_error = "Unable to create backup file at:".
                      ABSPATH."/wp-content/uploads/sucuri/$rand_file.zip ".
                      "ERROR: ".$backup_f->errorInfo(true);
        return(NULL);
    }

    if(filesize(ABSPATH."/wp-content/uploads/sucuri/$rand_file.zip") <= 5)
    {
        $USE_error = "Unable to create backup file (empty size).";
        unlink(ABSPATH."/wp-content/uploads/sucuri/$rand_file.zip");
        return(NULL);
    }
    $m5 = md5_file(ABSPATH."/wp-content/uploads/sucuri/$rand_file.zip");

    return($m5." ".site_url()."/wp-content/uploads/sucuri/$rand_file.zip");
}



/* Executes the database backup */
function sucuri_dobackup_db(&$USE_error)
{
    /* Creating backup file */
    if(!is_dir(ABSPATH."/wp-content/uploads/sucuri"))
    {
        mkdir(ABSPATH."/wp-content/uploads/sucuri");
        touch(ABSPATH."/wp-content/uploads/sucuri/index.html");
    }
    if(!is_readable(ABSPATH."/wp-content/uploads/sucuri/index.html"))
    {
        $USE_error = "Unable to create temporary files at:".ABSPATH."/wp-content/uploads/sucuri/";
        return(NULL);
    }

    $rand1 = rand();
    $rand_file = "db".md5($rand1)."-".time();
    $fh = gzopen(ABSPATH."/wp-content/uploads/sucuri/$rand_file.gz", "w");
    if(!$fh)
    {
        $USE_error = "Unable to create temporary db file at:".ABSPATH."/wp-content/uploads/sucuri/";
        return(NULL);
    }


    /* Connecting to the db to get the backup. */
    $db = mysql_connect(DB_HOST,DB_USER,DB_PASSWORD);
    if($db === FALSE)
    {
        $USE_error = "Unable to connect to database.";
        return(NULL);
    }
    mysql_select_db(DB_NAME, $db);

    $wptables = array();
    $dbresult = mysql_query('show tables', $db);
    while($row = mysql_fetch_row($dbresult))
    {
       $wptables[] = $row[0]; 
    }

    foreach($wptables as $mytable)
    {
        gzwrite($fh, "DROP TABLE IF EXISTS `$mytable`;\n".
                     "SET character_set_client = utf8;\n");
        $row = mysql_fetch_row(mysql_query('SHOW CREATE TABLE '.$mytable, $db));
        gzwrite($fh, $row[1].";\n\n");


        $dbresult = mysql_query("SELECT * FROM $mytable", $db);
        $result_count = mysql_num_fields($dbresult);
        for($i = 0; $i < $result_count; $i++)
        {
            while($row = mysql_fetch_row($dbresult))
            {
                gzwrite($fh, "INSERT INTO $mytable VALUES(");
                for($j = 0; $j < $result_count; $j++)
                {
                    if($j < ($result_count-1)) 
                    {
                        $add_comm = ",";
                    }
                    else
                    {
                        $add_comm = "";
                    }
                    if(!isset($row[$j]))
                    {
                        gzwrite($fh, '""'.$add_comm);
                        continue;
                    }
                    $row[$j] = addslashes($row[$j]);
                    $row[$j] = str_replace("\n", "\\n", $row[$j]);
                    $row[$j] = str_replace("\r", "\\r", $row[$j]);
                    $row[$j] = str_replace("\t", "\\t", $row[$j]);
                    gzwrite($fh, '"'.$row[$j].'"'.$add_comm);
                }
                gzwrite($fh, ");\n\n");
            }
        }
    }
    gzclose($fh);

    if(filesize(ABSPATH."/wp-content/uploads/sucuri/$rand_file.gz") <= 5)
    {
        $USE_error = "Unable to create DB backup file (empty size).";
        unlink(ABSPATH."/wp-content/uploads/sucuri/$rand_file.gz");
        return(NULL);
    }

    $m5 = md5_file(ABSPATH."/wp-content/uploads/sucuri/$rand_file.gz");
    return($m5." ".site_url()."/wp-content/uploads/sucuri/$rand_file.gz");
}



/* Scans all files. */
function sucuri_scanallfiles($dir, $output)
{
    $dh = opendir($dir);
    if(!$dh)
    {
        return(0);
    }
    $printdir = $dir;

    while (($myfile = readdir($dh)) !== false)
    {
        if($myfile == "." || $myfile == "..")
        {
            continue;
        }
        if(is_dir($dir."/".$myfile))
        {
            if(($myfile == "cache") && (strpos($dir, "wp-content") !== FALSE))
            {
                continue;
            }
            if(($myfile == "w3tc") && (strpos($dir."/".$myfile, "wp-content/w3tc") !== FALSE))
            {
                continue;
            }
            $output = sucuri_scanallfiles($dir."/".$myfile, $output);
        }
       
        else if((strpos($myfile, ".php") !== FALSE) ||
                (strpos($myfile, ".htm") !== FALSE) ||
                (strcmp($myfile, ".htaccess") == 0) ||
                (strcmp($myfile, "php.ini") == 0) ||
                (strpos($myfile, ".js") !== FALSE))
        {
            $output = $output.md5_file($dir."/".$myfile).filesize($dir."/".$myfile)." ".$dir."/".$myfile."\n";
        }

    }
    closedir($dh);
    return($output);
}



/* Executes the hourly scans. */
function sucuri_do_scan() 
{
    global $wp_version;
    $sucuri_wp_key = get_option('sucuri_wp_key');
    if($sucuri_wp_key === FALSE)
    {
        return(NULL);
    }

    if(sucuri_verify_run("sc", 7000) === FALSE)
    {
        return(NULL);
    }

    if(sucuri_backup_docheck("fs", 9000) == 1)
    {
        sucuri_send_log($sucuri_wp_key, "Warning: Latest file system backup failed. Please check your error logs for details. (possibly a PHP timeout).");
        sucuri_backup_docheck("fs", -1);
    }
    
    if(sucuri_backup_docheck("db", 9000) == 1)
    {
        sucuri_send_log($sucuri_wp_key, "Warning: Latest database backup failed. Please check your error logs for details. (possibly a PHP timeout).");
        sucuri_backup_docheck("db", -1);
    }

    $output = "";

    sucuri_send_log($sucuri_wp_key, "WordPress version: $wp_version", 1);
    if(strcmp($wp_version, "3.0.4") >= 0)
    {
        $output = sucuri_scanallfiles(ABSPATH, $output);
        sucuri_send_hashes($sucuri_wp_key, $output);
    }
}



/* Sends the hashes to sucuri. */
function sucuri_send_hashes($sucuri_wp_key, $final_message)
{
    $docurl = curl_init();
    curl_setopt($docurl, CURLOPT_URL, "https://wordpress.sucuri.net/");
    curl_setopt($docurl, CURLOPT_PORT , 443);
    curl_setopt($docurl, CURLOPT_VERBOSE, 0);
    curl_setopt($docurl, CURLOPT_HEADER, 0);
    curl_setopt($docurl, CURLOPT_SSLVERSION, 3);
    curl_setopt($docurl, CURLOPT_POST, 1);
    curl_setopt($docurl, CURLOPT_SSL_VERIFYPEER, 1);
    curl_setopt($docurl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($docurl, CURLOPT_POSTFIELDS, 
                         "k=$sucuri_wp_key&send-hashes=$final_message");

    $doresult = curl_exec($docurl);
    if(strpos($doresult,"ERROR:") === FALSE)
    {
        if(strpos($doresult, "ERROR: Invalid") !== FALSE)
        {
            delete_option('sucuri_wp_key');
        }
        return(1);
    }
    else
    {
        return(0);
    }
}



/* Blocks an IP via our plugin (wp-admin only). */
function sucuri_block_wpadmin($sucuri_wp_key)
{
    /* Creating backup file */
    if(!is_readable(ABSPATH."/wp-content/uploads/sucuri/block.php"))
    {
        @mkdir(ABSPATH."/wp-content/uploads/sucuri");
        touch(ABSPATH."/wp-content/uploads/sucuri/index.html");
        file_put_contents(ABSPATH."/wp-content/uploads/sucuri/block.php",
                          "<?php exit(0);\n");
    }
    if(!is_writeable(ABSPATH."/wp-content/uploads/sucuri/block.php"))
    {
        return(NULL);
    }

    file_put_contents(ABSPATH."/wp-content/uploads/sucuri/block.php",$_SERVER['REMOTE_ADDR']."\n",FILE_APPEND);
}



/* Blocks an IP address via .htaccess */
function sucuri_block_htaccess($sucuri_wp_key)
{
    if(isset($_SERVER['REMOTE_ADDR']) && strlen($_SERVER['REMOTE_ADDR']) > 4)
    {
        $remote_ip = $_SERVER['REMOTE_ADDR'];
    }
    else
    {
        sucuri_send_log($sucuri_wp_key, "IDS: UNABLE TO BLOCK IP Address via .htaccess: $remote_ip", 1);
        return(0);
    }

    $handle = fopen(ABSPATH."/.htaccess", "a");
    if(!$handle)
    {
        sucuri_send_log($sucuri_wp_key, "IDS: UNABLE TO BLOCK IP Address via .htaccess: $remote_ip", 1);
        return(0);
    }
    fwrite($handle, "\ndeny from $remote_ip #ADDED BY SUCURI\n");
    fclose($handle);

    sucuri_send_log($sucuri_wp_key, "IDS: IP Address blocked via .htaccess: $remote_ip", 1);
    return(1);
}



/* Sends the events to sucuri. */
function sucuri_send_log($sucuri_wp_key, $final_message, $ignore_res = 0)
{
    $docurl = curl_init();
    curl_setopt($docurl, CURLOPT_URL, "https://wordpress.sucuri.net/");
    curl_setopt($docurl, CURLOPT_PORT , 443);
    curl_setopt($docurl, CURLOPT_VERBOSE, 0);
    curl_setopt($docurl, CURLOPT_HEADER, 0);
    curl_setopt($docurl, CURLOPT_SSLVERSION, 3);
    curl_setopt($docurl, CURLOPT_POST, 1);
    curl_setopt($docurl, CURLOPT_SSL_VERIFYPEER, 1);
    curl_setopt($docurl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($docurl, CURLOPT_POSTFIELDS, 
                         "k=$sucuri_wp_key&send-event=$final_message");

    $doresult = curl_exec($docurl);
    if($ignore_res == 1)
    {
        return(1);
    }

    if(strpos($doresult,"ERROR:") !== FALSE)
    {
        if(strpos($doresult, "ERROR: Invalid") !== FALSE)
        {
            delete_option('sucuri_wp_key');
        }
        return(0);
    }
    else if(strpos($doresult, "ACTION: BLOCK HTACCESS") !== FALSE)
    {
        
        $re = get_option('sucuri_wp_re');
        if($re !== FALSE && $re == 'disabled')
        {
            return(1);
        }

        sucuri_block_htaccess($sucuri_wp_key);
        sucuri_block_wpadmin($sucuri_wp_key);
        return(1);
    }
    else
    {
        return(1);
    }
}



/* Generates an audit event. */
function sucuri_event($severity, $location, $message) 
{
    $severity = trim($severity);
    $location = trim($location);
    $message = trim($message);

	
    $username = NULL;
    $user = wp_get_current_user();
    if(!empty($user->ID))
    {
        $username = $user->user_login;
    }
    $time = date('Y-m-d H:i:s', time());
	

    /* Fixing severity */
    $severity = (int)$severity;
    if ($severity < 0)
    {
        $severity = 1;
    }
    else if($severity > 5)
    {
        $severity = 5;
    }
        
    /* Setting remote ip. */
    $remote_ip = "local";
    if(isset($_SERVER['REMOTE_ADDR']) && strlen($_SERVER['REMOTE_ADDR']) > 4)
    {
        $remote_ip = $_SERVER['REMOTE_ADDR'];
    }


    /* Setting header block */
    $header = NULL;
    if($username !== NULL)
    {
        $header = '['.$remote_ip.' '.$username.']';
    }
    else
    {
        $header = '['.$remote_ip.']';
    }


    /* Making sure we escape everything. */
    $header = htmlspecialchars($header);


    /* Getting severity. */
    $severityname = "Info";
    if($severity == 0)
    {
        $severityname = "Debug";
    }
    else if($severity == 1)
    {
        $severityname = "Notice";
    }
    else if($severity == 2)
    {
        $severityname = "Info";
    }
    else if($severity == 3)
    {
        $severityname = "Warning";
    }
    else if($severity == 4)
    {
        $severityname = "Error";
    }
    else if($severity == 5)
    {
        $severityname = "Critical";
    }

    $sucuri_wp_key = get_option('sucuri_wp_key');
    if($sucuri_wp_key !== FALSE)
    {
        sucuri_send_log($sucuri_wp_key, "$severityname: $header: $message");
    }

    return(true);
}



/** Hooks into WP **/


/* Detect plugins getting added/removed - and block IP addresses. */
add_action('admin_init', 'sucuri_events_without_actions');
add_action('login head', 'sucuri_events_without_actions');
add_action('wp_authenticate', 'sucuri_events_without_actions');
add_action('login_form', 'sucuri_events_without_actions');


/* Activation / Deactivation actions. */
register_activation_hook(__FILE__, 'sucuri_activate_scan');
register_deactivation_hook(__FILE__, 'sucuri_deactivate_scan');

/* Hooks our scanner function to the hourly cron. */
add_action('sucuri_hourly_scan', 'sucuri_do_scan');
add_action('sucuri_dailydb_scan', 'sucuri_dodailydb_scan');
add_action('sucuri_dailyfs_scan', 'sucuri_dodailyfs_scan');

/* Sucuri's admin menu. */
add_action('admin_menu', 'sucuri_menu');

/* Removing generator */
remove_action('wp_head', 'wp_generator');

/* Global hooks/actions */
include_once('sucuri_hooks.php');
include_once('sucuri_actions.php');
?>
