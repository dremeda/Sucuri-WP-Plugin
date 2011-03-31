<?php
/* Sucuri Security WordPress Plugin
 * Copyright (C) 2010 Sucuri Security - http://sucuri.net
 * Released under the GPL - see LICENSE file for details.
 */

function sucuri_add_attachment($id = NULL)
{
    if (is_numeric($id)) 
    {
        $postdata = get_post($id);
        $postname = $postdata->post_title;
    }
    sucuri_event(1, "core", "Attachment added to post. Id: $id, Name: $postname");
}


function sucuri_create_category($categoryid = NULL)
{
    if(is_numeric($categoryid))
    {
        $name = get_cat_name($categoryid);
    }
    sucuri_event(1, "core", "Category created. Id: $categoryid, Name: $name");
}

function sucuri_delete_post($id = NULL)
{
    sucuri_event(3, "core", "Post deleted. Id: $id");
}

function sucuri_private_to_published($id = NULL)
{
    if (is_numeric($id)) 
    {
        $postdata = get_post($id);
        $postname = $postdata->post_title;
    }
    sucuri_event(2, "core", "Post state changed from private to published. Id: $id, Name: $postname");
}

function sucuri_publish_post($id = NULL)
{
    if (is_numeric($id)) 
    {
        $postdata = get_post($id);
        $postname = $postdata->post_title;
    }
    sucuri_event(2, "core", "Post published (or edited after being published). Id: $id, Name: $postname");
}


function sucuri_comment_flood_trigger($oldtime = NULL, $newtime = NULL)
{
    sucuri_event(3, "core", "Commend flood triggered and blocked.");
}

function sucuri_comment_post($id = NULL, $status = NULL)
{
    $type = "spam";
    if(is_numeric($id))
    {
        $commentdata = get_comment($id);
        $postdata = get_post($commentdata->comment_post_ID);
        $postname = $postdata->post_title;

        if($status == 1)
        {
            $type = "approved";
        }
        else if($status == 0)
        {
            $type = "denied";
        }
    }
    //sucuri_event(1, "core", "Comment posted. Post: $postname, Comment id: $id, Type: $type");
}


function sucuri_add_link($id)
{
    if(is_numeric($id))
    {
        $linkdata = get_bookmark($id);
        $name = $linkdata->link_name;
        $url = $linkdata->link_url;
    }
    sucuri_event(2, "core", "New link added. Id: $id, Name: $name, URL: $url");
}


function sucuri_switch_theme($themename)
{
    sucuri_event(3, "core", "Theme modified to: $themename");
}

function sucuri_delete_user($id)
{
    sucuri_event(3, "core", "User deleted. Id: $id");
}

function sucuri_retrieve_password($name)
{
    sucuri_event(3, "core", "Password retrieval attempt by user $name");
}

function sucuri_user_register($id)
{
    if(is_numeric($id))
    {
        $userdata = get_userdata($id);
        $name = $userdata->display_name;
    }
    sucuri_event(3, "core", "New user registered: Id: $id, Name: $name");
}


function sucuri_wp_login($name)
{
    $displayname = get_profile('display_name', $name);

    sucuri_event(2, "core","User logged in. Name: $name");
}

function sucuri_wp_login_failed($name)
{
    sucuri_event(3, "core","User authentication failed. User name: $name");
}


function sucuri_reset_password($arg = NULL)
{
    if(isset($_GET['key']) )
    {
        /* Detecting wordpress 2.8.3 vulnerability - $key is array */
        if(is_array($_GET['key']))
        {
            sucuri_event(3, 'core', "IDS: Attempt to reset password by attacking wp2.8.3 bug.");
        }
    }
}


function sucuri_events_without_actions()
{
    /* Blocking IP addresses in our block list. */
    if(is_readable(ABSPATH."/wp-content/uploads/sucuri/block.php"))
    {
        $fh = fopen(ABSPATH."/wp-content/uploads/sucuri/block.php", "r");
        if($fh)
        {
            $fsize = filesize($log);
            if($fsize > 1000)
            {
                fseek($fh, -1000, SEEK_END);
                fgets($fh);
            }
            $ipc = $_SERVER['REMOTE_ADDR']."\n";

            while (!feof($fh))
            {
                $buffer = fgets($fh, 128);
                if(strlen($buffer) < 3)
                {
                    continue;
                }
      
                if(strcmp($buffer, $ipc) == 0)
                {
                    wp_die("Denied acccess by <a href='http://sucuri.net'>Sucuri</a>");
                }
            }
            fclose($fh);
        }
    }


    /* Plugin activated */
    if($_GET['action'] == "activate" && !empty($_GET['plugin']) && 
           strpos($_SERVER['REQUEST_URI'], 'plugins.php') !== false &&
           current_user_can('activate_plugins'))
    {
        $plugin = $_GET['plugin'];
        $plugin = strip_tags($plugin);
        $plugin = mysql_real_escape_string($plugin);
        sucuri_event(3, 'core', "Plugin activated: $plugin.");
    }

    /* Plugin deactivated */
    else if($_GET['action'] == "deactivate" && !empty($_GET['plugin']) && 
           strpos($_SERVER['REQUEST_URI'], 'plugins.php') !== false &&
           current_user_can('activate_plugins'))
    {
        $plugin = $_GET['plugin'];
        $plugin = strip_tags($plugin);
        $plugin = mysql_real_escape_string($plugin);
        sucuri_event(3, 'core', "Plugin deactivated: $plugin.");
    }

    /* Plugin updated */
    else if($_GET['action'] == "upgrade-plugin" && !empty($_GET['plugin']) && 
           strpos($_SERVER['REQUEST_URI'], 'wp-admin/update.php') !== false &&
           current_user_can('update_plugins'))
    {
        $plugin = $_GET['plugin'];
        $plugin = strip_tags($plugin);
        $plugin = mysql_real_escape_string($plugin);
        sucuri_event(3, 'core', "Plugin request to be updated: $plugin.");
    }

    /* WordPress updated */
    else if(isset($_POST['upgrade']) && isset($_POST['version']) && 
           strpos($_SERVER['REQUEST_URI'], 'update-core.php?action=do-core-reinstall') !== false &&
           current_user_can('update_core'))
    {
        $version = $_POST['version'];
        $version = strip_tags($version);
        $version = mysql_real_escape_string($version);
        sucuri_event(3, 'core', "WordPress updated (or re-installed) to version: $version.");
    }


}
?>
