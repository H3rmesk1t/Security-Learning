<?php
/**
 * PHPOK企业站系统，使用PHP语言及MySQL数据库编写的企业网站建设系统，基于LGPL协议开源授权
 * @package phpok
 * @author phpok.com
 * @copyright 2015-2016 深圳市锟铻科技有限公司
 * @version 4.x
 * @license http://www.phpok.com/lgpl.html PHPOK开源授权协议：GNU Lesser General Public License
**/

/**
 * 定义常量，所有PHP文件仅允许从这里入口
**/
define("PHPOK_SET",true);

/**
 * 定义**APP_ID**，不同**APP_ID**调用不同的文件
**/
define("APP_ID","www");

/**
 * 定义应用的根目录，如果程序出程，请将ROOT改为：define("ROOT","./");
**/
define("ROOT",str_replace("\\","/",dirname(__FILE__))."/");

/**
 * 网页根目录
**/
define('WEBROOT','.');

/**
 * 定义框架目录
**/
define("FRAMEWORK",ROOT."framework/");

/**
 * 定义数据文件目录
**/
define('DATA',ROOT.'_data/');

/**
 * 定义配置文件目录
**/
define('CONFIG',ROOT.'_config/');

/**
 * 定义缓存目录
**/
define('CACHE',ROOT.'_cache/');

/**
 * 定义 APP 目录，该目录用于系统应用程序读取，仅限官方扩展开发应用
**/
define('OKAPP',ROOT.'_app/');

/**
 * 定义扩展库目录
**/
define('EXTENSION',ROOT.'extension/');

/**
 * 定义插件目录
**/
define('PLUGIN',ROOT.'plugins/');

/**
 * 定义网关路由目录
**/
define('GATEWAY',ROOT.'gateway/');



/**
 * 检测是否已安装，如未安装跳转到安装页面，建议您在安装成功后去除这个判断。
**/
if(!file_exists(DATA."install.lock")){
	header("Location:phpokinstall.php");
	exit;
}

/**
 * 引入初始化文件
**/
require(FRAMEWORK.'init.php');